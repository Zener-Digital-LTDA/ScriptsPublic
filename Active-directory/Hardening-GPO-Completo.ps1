<#
=====================================================================
 Hardening-GPO-Completo.ps1
 PARTE 1 - Senha / Bloqueio de conta / Auditoria (Default Domain Policy)
 PARTE 2 - Localizacao padrao onde novos computadores caem no dominio
 PARTE 3 - LAPS (schema, delegacao, GPO dedicada)

 Requisitos gerais:
   - Rodar num DC ou maquina com RSAT (modulos GroupPolicy, ActiveDirectory,
     NetSecurity e, para a Parte 3, o modulo LAPS)
   - Conta com permissao adequada (Domain Admin recomendado para as
     partes que tocam schema e Default Domain Policy)
=====================================================================
#>

Import-Module GroupPolicy
Import-Module ActiveDirectory

$ErrorActionPreference = "Stop"

# Log em arquivo, para o caso do script rodar sem ninguem acompanhando a tela
if (-not (Test-Path "C:\Scripts")) { New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null }
$logTranscript = "C:\Scripts\Hardening-GPO-Completo_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
try {
    Start-Transcript -Path $logTranscript -Append | Out-Null
    Write-Host "Log desta execucao sendo salvo em: $logTranscript" -ForegroundColor DarkGray
} catch {
    Write-Host "Nao foi possivel iniciar o log em arquivo (Start-Transcript). Continuando so com saida no console." -ForegroundColor Yellow
}

#region ========================= FUNCOES AUXILIARES =========================

function Read-NumeroValidado {
    param([string]$Pergunta, [int]$Default, [int]$Min, [int]$Max)
    while ($true) {
        $entrada = Read-Host "$Pergunta (padrao: $Default | minimo: $Min | maximo: $Max) [Enter = padrao]"
        if ([string]::IsNullOrWhiteSpace($entrada)) { return $Default }
        if ($entrada -notmatch '^\d+$') { Write-Host "Digite apenas numeros." -ForegroundColor Yellow; continue }
        $valor = [int]$entrada
        if ($valor -lt $Min -or $valor -gt $Max) { Write-Host "Valor fora do intervalo permitido ($Min a $Max)." -ForegroundColor Yellow; continue }
        return $valor
    }
}

function Read-SimNao {
    param([string]$Pergunta, [string]$PadraoS_N = "N")
    $resp = Read-Host "$Pergunta (S/N) [Enter = $PadraoS_N]"
    if ([string]::IsNullOrWhiteSpace($resp)) { $resp = $PadraoS_N }
    return ($resp -match '^[Ss]')
}

# Edita (ou cria) o GptTmpl.inf de uma GPO diretamente no SYSVOL, preservando
# o que ja existir, e depois registra a extensao de Security Settings e
# incrementa a versao da GPO no AD para que ela seja reprocessada.
# Isso e necessario porque Senha/Bloqueio/Auditoria/Restricted Groups NAO
# sao valores de registro - vivem nesse arquivo de template de seguranca.
function Set-GPOSecurityTemplate {
    param(
        [Parameter(Mandatory)] [string]$GpoName,
        [Parameter(Mandatory)] [hashtable]$Secoes   # ex: @{ "System Access" = @{ Chave = Valor } }
    )

    $gpo = Get-GPO -Name $GpoName
    $guid = "{" + $gpo.Id.ToString().ToUpper() + "}"
    $dominio = $gpo.DomainName
    $pastaGpo = "\\$dominio\SYSVOL\$dominio\Policies\$guid"
    $pastaSecEdit = "$pastaGpo\Machine\Microsoft\Windows NT\SecEdit"
    $arquivoInf = "$pastaSecEdit\GptTmpl.inf"

    if (-not (Test-Path $pastaSecEdit)) {
        New-Item -ItemType Directory -Path $pastaSecEdit -Force | Out-Null
    }

    # Le o conteudo existente para nao perder outras configuracoes ja aplicadas
    $conteudo = [ordered]@{}
    if (Test-Path $arquivoInf) {
        $secaoAtual = $null
        foreach ($linha in Get-Content -Path $arquivoInf -Encoding Unicode) {
            if ($linha -match '^\[(.+)\]\s*$') {
                $secaoAtual = $matches[1]
                if (-not $conteudo.Contains($secaoAtual)) { $conteudo[$secaoAtual] = [ordered]@{} }
            }
            elseif ($secaoAtual -and $linha -match '^(.*?)\s*=\s*(.*)$') {
                $conteudo[$secaoAtual][$matches[1].Trim()] = $matches[2].Trim()
            }
        }
    }

    if (-not $conteudo.Contains("Unicode")) { $conteudo["Unicode"] = [ordered]@{ "Unicode" = "yes" } }
    if (-not $conteudo.Contains("Version"))  { $conteudo["Version"] = [ordered]@{ "signature" = '"$CHICAGO$"'; "Revision" = "1" } }

    foreach ($secao in $Secoes.Keys) {
        if (-not $conteudo.Contains($secao)) { $conteudo[$secao] = [ordered]@{} }
        foreach ($chave in $Secoes[$secao].Keys) {
            $conteudo[$secao][$chave] = $Secoes[$secao][$chave]
        }
    }

    $ordemPreferida = @("Unicode","Version","System Access","Event Audit","Registry Values","Privilege Rights","Group Membership")
    $ordemFinal = $ordemPreferida | Where-Object { $conteudo.Contains($_) }
    $ordemFinal += $conteudo.Keys | Where-Object { $ordemPreferida -notcontains $_ }

    $linhas = @()
    foreach ($secao in $ordemFinal) {
        $linhas += "[$secao]"
        foreach ($chave in $conteudo[$secao].Keys) {
            $linhas += "$chave = $($conteudo[$secao][$chave])"
        }
        $linhas += ""
    }

    Set-Content -Path $arquivoInf -Value $linhas -Encoding Unicode

    # Garante que a extensao "Security Settings" esteja registrada na GPO
    $cseSeguranca = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
    $objAD = Get-ADObject -Identity $gpo.Path -Properties gPCMachineExtensionNames, versionNumber

    $extAtual = $objAD.gPCMachineExtensionNames
    if ([string]::IsNullOrEmpty($extAtual)) {
        $novoExt = $cseSeguranca
    } elseif ($extAtual.IndexOf($cseSeguranca, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $novoExt = "$extAtual$cseSeguranca"
    } else {
        $novoExt = $extAtual
    }

    # versionNumber e um inteiro de 32 bits: word alto = versao "Machine",
    # word baixo = versao "User". Incrementamos so a parte Machine.
    $verAtual   = [uint32]$objAD.versionNumber
    $verUser    = $verAtual -band 0xFFFF
    $verMach    = (($verAtual -shr 16) -band 0xFFFF) + 1
    $novaVersao = ($verMach -shl 16) -bor $verUser

    Set-ADObject -Identity $gpo.Path -Replace @{ gPCMachineExtensionNames = $novoExt; versionNumber = $novaVersao }

    $gptIni = "$pastaGpo\GPT.INI"
    if (Test-Path $gptIni) {
        (Get-Content $gptIni) -replace '(?m)^Version=\d+', "Version=$novaVersao" | Set-Content $gptIni
    }

    Write-Host "  Template de seguranca atualizado: $arquivoInf" -ForegroundColor DarkGray
    Write-Host "  Versao da GPO incrementada para: $novaVersao" -ForegroundColor DarkGray
}

# Detecta/cria a OU PRINCIPAL da empresa - perguntado apenas UMA vez,
# e reaproveitado no resto do script (cache em $script:ouEmpresaDN).
$script:ouEmpresaDN = $null

function Get-OUEmpresaPrincipal {
    if ($script:ouEmpresaDN) { return $script:ouEmpresaDN }

    Write-Host "`n=== OU principal da empresa ===" -ForegroundColor Cyan
    $domainDN = (Get-ADDomain).DistinguishedName
    $ousTopo = Get-ADOrganizationalUnit -SearchBase $domainDN -SearchScope OneLevel -Filter * | Sort-Object DistinguishedName

    if ($ousTopo.Count -eq 0) {
        Write-Host "Nenhuma OU de topo encontrada no dominio ainda." -ForegroundColor Yellow
    } else {
        $i = 1
        foreach ($ou in $ousTopo) {
            Write-Host ("  {0,2}) {1}" -f $i, $ou.DistinguishedName)
            $i++
        }
    }
    Write-Host ("  {0,2}) Criar uma nova OU principal (ex.: 'Empresa')" -f ($ousTopo.Count + 1))

    while ($true) {
        $escolha = Read-Host "`nEscolha a OU principal da empresa"
        if ($escolha -notmatch '^\d+$') { Write-Host "Digite um numero valido." -ForegroundColor Yellow; continue }
        $n = [int]$escolha

        if ($n -ge 1 -and $n -le $ousTopo.Count) {
            $script:ouEmpresaDN = $ousTopo[$n - 1].DistinguishedName
            return $script:ouEmpresaDN
        }
        elseif ($n -eq ($ousTopo.Count + 1)) {
            $nomeEmpresa = Read-Host "Nome da OU principal (ex.: 'Empresa')"
            New-ADOrganizationalUnit -Name $nomeEmpresa -Path $domainDN -ProtectedFromAccidentalDeletion $true
            $script:ouEmpresaDN = "OU=$nomeEmpresa,$domainDN"
            Write-Host "OU principal '$nomeEmpresa' criada em $domainDN" -ForegroundColor Green
            return $script:ouEmpresaDN
        }
        else {
            Write-Host "Opcao invalida." -ForegroundColor Yellow
        }
    }
}

function Select-OU {
    param([string]$Titulo = "Selecione a OU de destino")

    $ouEmpresa = Get-OUEmpresaPrincipal

    Write-Host "`n=== $Titulo ===" -ForegroundColor Cyan
    $ous = Get-ADOrganizationalUnit -SearchBase $ouEmpresa -SearchScope OneLevel -Filter * | Sort-Object DistinguishedName

    Write-Host ("  {0,2}) {1}   <- OU principal (aplica para TODAS as sub-OUs abaixo, via heranca)" -f 0, $ouEmpresa)
    if ($ous.Count -eq 0) {
        Write-Host "Nenhuma sub-OU encontrada dentro de $ouEmpresa ainda." -ForegroundColor Yellow
    } else {
        $i = 1
        foreach ($ou in $ous) {
            Write-Host ("  {0,2}) {1}" -f $i, $ou.DistinguishedName)
            $i++
        }
    }
    Write-Host ("  {0,2}) Digitar um Distinguished Name manualmente" -f ($ous.Count + 1))
    Write-Host ("  {0,2}) Criar uma nova sub-OU dentro de $ouEmpresa" -f ($ous.Count + 2))

    while ($true) {
        $escolha = Read-Host "`nDigite o numero da opcao desejada"
        if ($escolha -notmatch '^\d+$') { Write-Host "Digite um numero valido." -ForegroundColor Yellow; continue }
        $n = [int]$escolha

        if ($n -eq 0) {
            return $ouEmpresa
        }
        elseif ($n -ge 1 -and $n -le $ous.Count) {
            return $ous[$n - 1].DistinguishedName
        }
        elseif ($n -eq ($ous.Count + 1)) {
            return (Read-Host "Digite o Distinguished Name completo")
        }
        elseif ($n -eq ($ous.Count + 2)) {
            $nomeFilha = Read-Host "Nome da nova sub-OU (ex.: 'Computadores')"
            $ouFilhaDN = "OU=$nomeFilha,$ouEmpresa"
            if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouFilhaDN'" -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $nomeFilha -Path $ouEmpresa -ProtectedFromAccidentalDeletion $true
                Write-Host "Sub-OU '$nomeFilha' criada em $ouEmpresa" -ForegroundColor Green
            }
            return $ouFilhaDN
        }
        else {
            Write-Host "Opcao invalida." -ForegroundColor Yellow
        }
    }
}

#endregion

Write-Host "`n#####################################################################" -ForegroundColor Cyan
Write-Host "#  PARTE 1 - SENHA, BLOQUEIO DE CONTA E AUDITORIA (Default Domain Policy)" -ForegroundColor Cyan
Write-Host "#####################################################################`n" -ForegroundColor Cyan

Write-Host "Lembrete: politica de senha/bloqueio de dominio SO tem efeito quando" -ForegroundColor DarkYellow
Write-Host "configurada na Default Domain Policy (GPO vinculada na raiz do dominio)." -ForegroundColor DarkYellow
Write-Host "Nao existe escolha de OU aqui por esse motivo.`n" -ForegroundColor DarkYellow

$rodarParte1 = Read-SimNao -Pergunta "Deseja configurar agora a politica de senha/bloqueio/auditoria" -PadraoS_N "S"

if ($rodarParte1) {

    $minPwdLength = Read-NumeroValidado -Pergunta "Tamanho minimo da senha" -Default 9 -Min 7 -Max 30

    Write-Host "`nComplexidade de senha: SEMPRE ATIVADA. Essa regra nao pode ser desabilitada." -ForegroundColor Yellow

    $maxPwdAge = Read-NumeroValidado -Pergunta "Validade maxima da senha (dias)" -Default 60 -Min 1 -Max 150

    do {
        $avisoExpiracao = Read-NumeroValidado -Pergunta "Avisar expiracao com quantos dias de antecedencia" -Default 7 -Min 1 -Max ($maxPwdAge - 1)
    } while ($avisoExpiracao -ge $maxPwdAge)

    $historicoSenhas = Read-NumeroValidado -Pergunta "Quantas senhas anteriores lembrar (historico)" -Default 4 -Min 0 -Max 24

    Write-Host "`nPolitica de bloqueio de conta (valores padrao: 3 tentativas / 10 minutos)." -ForegroundColor Cyan
    $lockoutThreshold = Read-NumeroValidado -Pergunta "Tentativas de senha incorreta antes de bloquear a conta" -Default 3 -Min 1 -Max 999
    $lockoutDuration  = Read-NumeroValidado -Pergunta "Tempo de bloqueio da conta (minutos)" -Default 10 -Min 1 -Max 99999
    $lockoutReset     = Read-NumeroValidado -Pergunta "Apos quantos minutos o contador de tentativas reinicia" -Default 10 -Min 1 -Max $lockoutDuration
    Write-Host "  Obs.: a conta 'Administrator' embutida do AD ja e isenta de bloqueio por padrao." -ForegroundColor DarkYellow

    Write-Host "`n--- Resumo final antes de aplicar ---" -ForegroundColor Cyan
    [PSCustomObject]@{
        "Tamanho minimo senha"    = $minPwdLength
        "Complexidade"            = "Ativada (fixo)"
        "Validade maxima (dias)"  = $maxPwdAge
        "Aviso expiracao (dias)"  = $avisoExpiracao
        "Historico de senhas"     = $historicoSenhas
        "Tentativas p/ bloqueio"  = $lockoutThreshold
        "Duracao bloqueio (min)"  = $lockoutDuration
        "Reset contador (min)"    = $lockoutReset
        "Auditoria account logon" = "Sucesso e Falha"
        "Auditoria logon events"  = "Sucesso e Falha"
    } | Format-List

    if (Read-SimNao -Pergunta "Confirma a aplicacao na 'Default Domain Policy'" -PadraoS_N "S") {

        $pastaBackup = "C:\Backups\GPO\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $pastaBackup -Force | Out-Null
        Backup-GPO -Name "Default Domain Policy" -Path $pastaBackup | Out-Null
        Write-Host "Backup salvo em: $pastaBackup" -ForegroundColor Green

        Set-GPRegistryValue -Name "Default Domain Policy" `
            -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
            -ValueName "PasswordExpiryWarning" -Type DWord -Value $avisoExpiracao | Out-Null

        Set-GPOSecurityTemplate -GpoName "Default Domain Policy" -Secoes @{
            "System Access" = @{
                "MinimumPasswordLength" = $minPwdLength
                "PasswordComplexity"    = 1
                "MaximumPasswordAge"    = $maxPwdAge
                "PasswordHistorySize"   = $historicoSenhas
                "LockoutBadCount"       = $lockoutThreshold
                "LockoutDuration"       = $lockoutDuration
                "ResetLockoutCount"     = $lockoutReset
            }
            "Event Audit" = @{
                "AuditAccountLogon" = 3
                "AuditLogonEvents"  = 3
            }
        }
        Write-Host "Parte 1 aplicada com sucesso!" -ForegroundColor Green
    } else {
        Write-Host "Parte 1 cancelada pelo usuario." -ForegroundColor Yellow
    }
}

Write-Host "`n#####################################################################" -ForegroundColor Cyan
Write-Host "#  PARTE 2 - LOCALIZACAO PADRAO DOS COMPUTADORES NO DOMINIO" -ForegroundColor Cyan
Write-Host "#####################################################################`n" -ForegroundColor Cyan

Write-Host "Por padrao, o AD joga maquinas novas no container 'CN=Computers'," -ForegroundColor DarkYellow
Write-Host "que NAO e uma OU e nao recebe GPO. O recomendado e redirecionar para" -ForegroundColor DarkYellow
Write-Host "uma OU real, ex.: OU=Computadores,OU=Empresa,DC=...`n" -ForegroundColor DarkYellow

if (Read-SimNao -Pergunta "Deseja alterar/definir o local padrao onde novos computadores entram no dominio") {
    $ouComputadores = Select-OU -Titulo "OU padrao para novos computadores"
    Write-Host "Aplicando redirecionamento para: $ouComputadores" -ForegroundColor Cyan
    & redircmp.exe $ouComputadores
    Write-Host "Redirecionamento aplicado (redircmp)." -ForegroundColor Green
} else {
    Write-Host "Mantendo o local padrao (CN=Computers)." -ForegroundColor Yellow
}

Write-Host "`n#####################################################################" -ForegroundColor Cyan
Write-Host "#  PARTE 3 - LAPS" -ForegroundColor Cyan
Write-Host "#####################################################################`n" -ForegroundColor Cyan

if (Read-SimNao -Pergunta "Deseja habilitar o LAPS agora") {

    Import-Module LAPS -ErrorAction Stop

    $nomeGpoLaps = Read-Host "Digite o nome da nova GPO do LAPS"
    $ouLaps = Select-OU -Titulo "OU onde o LAPS sera aplicado (schema, delegacao e GPO)"

    # ---------- checagem best-effort de Schema Admins ----------
    try {
        $membroSchemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -Recursive |
            Where-Object { $_.SamAccountName -eq $env:USERNAME }
        if (-not $membroSchemaAdmins) {
            Write-Host "ATENCAO: seu usuario nao aparenta estar no grupo 'Schema Admins'." -ForegroundColor Red
            Write-Host "A extensao de schema (Etapa 1) vai falhar sem essa permissao." -ForegroundColor Red
        }
    } catch {
        Write-Host "Nao foi possivel checar automaticamente o grupo Schema Admins. Confirme manualmente." -ForegroundColor Yellow
    }

    Write-Host "`nATENCAO: a extensao de schema do LAPS e uma operacao UNICA e" -ForegroundColor Red
    Write-Host "IRREVERSIVEL para todo o dominio. So precisa ser feita uma vez." -ForegroundColor Red

    if (Read-SimNao -Pergunta "Confirma executar a extensao de schema agora (pule se ja foi feita antes)") {
        Update-LapsADSchema -Confirm:$false
        Write-Host "Schema estendido." -ForegroundColor Green
    }

    # ---------- Etapa 2: permissao Self ----------
    Set-LapsADComputerSelfPermission -Identity $ouLaps
    Write-Host "Permissao de escrita (Self) aplicada na OU $ouLaps" -ForegroundColor Green

    # ---------- Etapa 3: permissao de leitura ----------
    $grupoLeitura = Read-Host "Nome do grupo que podera LER as senhas do LAPS (Enter = LAPS-TI)"
    if ([string]::IsNullOrWhiteSpace($grupoLeitura)) { $grupoLeitura = "LAPS-TI" }

    $grupoExistente = Get-ADGroup -Filter "Name -eq '$grupoLeitura'" -ErrorAction SilentlyContinue

    if (-not $grupoExistente) {
        Write-Host "Grupo '$grupoLeitura' nao existe ainda. Vamos cria-lo." -ForegroundColor Yellow
        $ouGrupo = Select-OU -Titulo "OU onde o grupo '$grupoLeitura' sera criado"
        New-ADGroup -Name $grupoLeitura -GroupScope Global -GroupCategory Security -Path $ouGrupo
        Write-Host "Grupo '$grupoLeitura' criado em $ouGrupo" -ForegroundColor Green

        # Membros padrao que sempre entram nesse grupo
        $membrosPadrao = @("Administrator", "help.zener")
        foreach ($membro in $membrosPadrao) {
            try {
                Add-ADGroupMember -Identity $grupoLeitura -Members $membro
                Write-Host "  Membro padrao adicionado: $membro" -ForegroundColor Green
            } catch {
                Write-Host "  Nao foi possivel adicionar '$membro' automaticamente (confira se a conta existe no AD). Adicione manualmente depois." -ForegroundColor Yellow
            }
        }
        Write-Host "Os demais membros do grupo devem ser adicionados manualmente (ADUC ou Add-ADGroupMember)." -ForegroundColor Cyan
    } else {
        Write-Host "Grupo '$grupoLeitura' ja existe, reaproveitando." -ForegroundColor Green
    }

    $grupoQualificado = "$env:USERDOMAIN\$grupoLeitura"
    Set-LapsADReadPasswordPermission -Identity $ouLaps -AllowedPrincipals $grupoQualificado
    Write-Host "Permissao de leitura concedida a $grupoQualificado na OU $ouLaps" -ForegroundColor Green

    if (Read-SimNao -Pergunta "Deseja validar as permissoes aplicadas (dsacls)") {
        Write-Host "`n--- Permissao de leitura (grupo) ---" -ForegroundColor Cyan
        dsacls $ouLaps | Select-String $grupoLeitura
        Write-Host "`n--- Permissao de escrita (Self) ---" -ForegroundColor Cyan
        dsacls $ouLaps | Select-String "SELF"
    }

    # ---------- Etapa 4: criar e vincular a GPO (com checagem de reexecucao) ----------
    $gpoLapsExistente = Get-GPO -Name $nomeGpoLaps -ErrorAction SilentlyContinue
    if ($gpoLapsExistente) {
        Write-Host "GPO '$nomeGpoLaps' ja existe." -ForegroundColor Yellow
        if (Read-SimNao -Pergunta "Deseja reconfigurar essa GPO existente (reaplicar as configuracoes nela)" -PadraoS_N "S") {
            Write-Host "Reutilizando GPO existente '$nomeGpoLaps'." -ForegroundColor Green
            try { New-GPLink -Name $nomeGpoLaps -Target $ouLaps -ErrorAction Stop | Out-Null } catch { }
        } else {
            do {
                $nomeGpoLaps = Read-Host "Digite um novo nome para a GPO do LAPS"
                $gpoLapsExistente = Get-GPO -Name $nomeGpoLaps -ErrorAction SilentlyContinue
                if ($gpoLapsExistente) { Write-Host "Esse nome tambem ja existe." -ForegroundColor Yellow }
            } while ($gpoLapsExistente)
            New-GPO -Name $nomeGpoLaps -Comment "GPO do LAPS criada via script em $(Get-Date -Format 'dd/MM/yyyy HH:mm')" | Out-Null
            New-GPLink -Name $nomeGpoLaps -Target $ouLaps | Out-Null
            Write-Host "GPO '$nomeGpoLaps' criada e vinculada em $ouLaps" -ForegroundColor Green
        }
    } else {
        New-GPO -Name $nomeGpoLaps -Comment "GPO do LAPS criada via script em $(Get-Date -Format 'dd/MM/yyyy HH:mm')" | Out-Null
        New-GPLink -Name $nomeGpoLaps -Target $ouLaps | Out-Null
        Write-Host "GPO '$nomeGpoLaps' criada e vinculada em $ouLaps" -ForegroundColor Green
    }

    # ---------- Configuracoes de senha do LAPS ----------
    Write-Host "`n--- Configuracao das regras de senha do LAPS ---" -ForegroundColor Cyan
    Write-Host "Backup directory: Active Directory (fixo)." -ForegroundColor Yellow
    Write-Host "Complexidade da senha:" -ForegroundColor Cyan
    Write-Host "  1) Maiusculas apenas"
    Write-Host "  2) Maiusculas + minusculas"
    Write-Host "  3) Maiusculas + minusculas + numeros  (padrao)"
    Write-Host "  4) Maiusculas + minusculas + numeros + simbolos"
    $complexEscolha = Read-Host "Escolha (Enter = 3)"
    if ([string]::IsNullOrWhiteSpace($complexEscolha)) { $complexEscolha = 3 }
    $complexEscolha = [int]$complexEscolha

    $lapsLength   = Read-NumeroValidado -Pergunta "Tamanho da senha gerenciada pelo LAPS" -Default 16 -Min 8 -Max 64
    $lapsAge      = Read-NumeroValidado -Pergunta "Idade maxima da senha do LAPS (dias)" -Default 30 -Min 1 -Max 365
    $lapsHistorico = Read-NumeroValidado -Pergunta "Tamanho do historico de senhas criptografadas" -Default 3 -Min 0 -Max 12
    $lapsGraca    = Read-NumeroValidado -Pergunta "Periodo de carencia pos-autenticacao (horas)" -Default 24 -Min 1 -Max 72

    $contaCustom = Read-Host "Nome de conta local customizada a gerenciar (Enter = usar 'Administrator' padrao)"

    $chaveLaps = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "BackupDirectory"               -Type DWord -Value 1               | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "PasswordComplexity"             -Type DWord -Value $complexEscolha  | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "PasswordLength"                 -Type DWord -Value $lapsLength      | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "PasswordAgeDays"                -Type DWord -Value $lapsAge         | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "ADPasswordEncryptionEnabled"    -Type DWord -Value 1                | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "PasswordHistorySize"            -Type DWord -Value $lapsHistorico   | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "PostAuthenticationActions"      -Type DWord -Value 3                | Out-Null
    Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "PostAuthenticationResetDelay"   -Type DWord -Value $lapsGraca        | Out-Null

    if (-not [string]::IsNullOrWhiteSpace($contaCustom)) {
        Set-GPRegistryValue -Name $nomeGpoLaps -Key $chaveLaps -ValueName "AdministratorAccountName" -Type String -Value $contaCustom | Out-Null
        Write-Host "Conta gerenciada customizada: $contaCustom" -ForegroundColor Green
    } else {
        Write-Host "Mantendo a conta 'Administrator' padrao como gerenciada." -ForegroundColor Yellow
    }

    # ---------- Habilitar a conta Administrator local (Security Options -> System Access) ----------
    if (Read-SimNao -Pergunta "Habilitar a conta 'Administrator' local nessa GPO (necessario para o LAPS gerenciar)" -PadraoS_N "S") {
        Set-GPOSecurityTemplate -GpoName $nomeGpoLaps -Secoes @{
            "System Access" = @{ "EnableAdminAccount" = 1 }
        }
        Write-Host "Conta Administrator habilitada via GPO." -ForegroundColor Green
    }

    Write-Host "`nLAPS configurado com sucesso!" -ForegroundColor Green
    Write-Host "Se a pasta 'LAPS' nao aparecer em Administrative Templates no GPMC," -ForegroundColor Yellow
    Write-Host "copie LAPS.admx/LAPS.adml para o Central Store em SYSVOL\...\PolicyDefinitions." -ForegroundColor Yellow

    Write-Host "`n--- Testes sugeridos (rodar manualmente depois do gpupdate) ---" -ForegroundColor Cyan
    Write-Host "  gpupdate /force"
    Write-Host "  Invoke-LapsPolicyProcessing"
    Write-Host "  Get-LapsDiagnostics -Verbose"
}

Write-Host "`n#####################################################################" -ForegroundColor Cyan
Write-Host "#  PARTE 4 - RESTRICTED GROUPS (Administradores locais)" -ForegroundColor Cyan
Write-Host "#####################################################################`n" -ForegroundColor Cyan

if (Read-SimNao -Pergunta "Deseja configurar Restricted Groups (grupo Administradores local)") {

    Write-Host "`nATENCAO: Restricted Groups no modo 'Members' SUBSTITUI totalmente" -ForegroundColor Red
    Write-Host "a lista de membros do grupo Administradores local. Qualquer conta ou" -ForegroundColor Red
    Write-Host "grupo que nao estiver na lista sera REMOVIDO no proximo gpupdate," -ForegroundColor Red
    Write-Host "inclusive o 'Domain Admins', se voce nao incluir explicitamente." -ForegroundColor Red

    $manterDomainAdmins = Read-SimNao -Pergunta "Manter 'Domain Admins' tambem no Administradores local (recomendado)" -PadraoS_N "S"

    $membrosRestricted = New-Object System.Collections.Generic.List[string]
    $membrosRestricted.Add("$env:USERDOMAIN\Administrator")
    $membrosRestricted.Add("$env:USERDOMAIN\help.zener")
    if ($manterDomainAdmins) { $membrosRestricted.Add("$env:USERDOMAIN\Domain Admins") }

    Write-Host "`nMembros fixos que serao aplicados: $($membrosRestricted -join ', ')" -ForegroundColor Cyan
    Write-Host "Os demais membros podem ser adicionados depois, editando a GPO manualmente." -ForegroundColor Cyan

    $nomeGpoRestricted = Read-Host "Digite o nome da GPO de Restricted Groups"
    $ouRestricted = Select-OU -Titulo "OU onde aplicar Restricted Groups"

    $gpoRestrictedExistente = Get-GPO -Name $nomeGpoRestricted -ErrorAction SilentlyContinue
    if ($gpoRestrictedExistente) {
        Write-Host "GPO '$nomeGpoRestricted' ja existe." -ForegroundColor Yellow
        if (Read-SimNao -Pergunta "Deseja reconfigurar essa GPO existente (reaplicar Restricted Groups nela)" -PadraoS_N "S") {
            Write-Host "Reutilizando GPO existente '$nomeGpoRestricted'." -ForegroundColor Green
            try { New-GPLink -Name $nomeGpoRestricted -Target $ouRestricted -ErrorAction Stop | Out-Null } catch { }
        } else {
            do {
                $nomeGpoRestricted = Read-Host "Digite um novo nome para a GPO"
                $gpoRestrictedExistente = Get-GPO -Name $nomeGpoRestricted -ErrorAction SilentlyContinue
                if ($gpoRestrictedExistente) { Write-Host "Esse nome tambem ja existe." -ForegroundColor Yellow }
            } while ($gpoRestrictedExistente)
            New-GPO -Name $nomeGpoRestricted -Comment "Restricted Groups - Administradores locais - $(Get-Date -Format 'dd/MM/yyyy HH:mm')" | Out-Null
            New-GPLink -Name $nomeGpoRestricted -Target $ouRestricted | Out-Null
            Write-Host "GPO '$nomeGpoRestricted' criada e vinculada em $ouRestricted" -ForegroundColor Green
        }
    } else {
        New-GPO -Name $nomeGpoRestricted -Comment "Restricted Groups - Administradores locais - $(Get-Date -Format 'dd/MM/yyyy HH:mm')" | Out-Null
        New-GPLink -Name $nomeGpoRestricted -Target $ouRestricted | Out-Null
        Write-Host "GPO '$nomeGpoRestricted' criada e vinculada em $ouRestricted" -ForegroundColor Green
    }

    $listaMembros = $membrosRestricted -join ","

    Set-GPOSecurityTemplate -GpoName $nomeGpoRestricted -Secoes @{
        "Group Membership" = @{ "*S-1-5-32-544__Members" = $listaMembros }
    }

    Write-Host "Restricted Groups aplicado! Administradores local = $listaMembros" -ForegroundColor Green
    Write-Host "Confira no GPMC (Computer Config > Policies > Windows Settings > Security Settings > Restricted Groups) se ficou como esperado." -ForegroundColor Yellow
}

Write-Host "`n===================== SCRIPT FINALIZADO =====================" -ForegroundColor Cyan

if (Read-SimNao -Pergunta "Deseja rodar agora a validacao das atividades efetuadas" -PadraoS_N "S") {
    $caminhoValidacao = "C:\Scripts\Valida-Hardening-GPO.ps1"
    if (Test-Path $caminhoValidacao) {
        & $caminhoValidacao
    } else {
        Write-Host "Nao encontrei o script de validacao em $caminhoValidacao" -ForegroundColor Red
        Write-Host "Confira se ele foi baixado/colocado nesse caminho e rode manualmente." -ForegroundColor Yellow
    }
}

try { Stop-Transcript | Out-Null } catch { }

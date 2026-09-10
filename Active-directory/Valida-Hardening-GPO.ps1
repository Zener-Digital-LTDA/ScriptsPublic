<#
=====================================================================
 Valida-Hardening-GPO.ps1
 Confere, direto no AD/SYSVOL, se as GPOs foram criadas, vinculadas
 e se as configuracoes que o script principal aplicou realmente
 estao la. Nao depende de nenhuma maquina cliente ter feito gpupdate.
=====================================================================
#>

Import-Module GroupPolicy
Import-Module ActiveDirectory

function Mostrar-Cabecalho {
    param([string]$Texto)
    Write-Host "`n=====================================================================" -ForegroundColor Cyan
    Write-Host $Texto -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan
}

function Ler-GptTmpl {
    param([string]$GpoName)
    try {
        $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    } catch {
        Write-Host "GPO '$GpoName' NAO ENCONTRADA." -ForegroundColor Red
        return $null
    }
    $guid = "{" + $gpo.Id.ToString().ToUpper() + "}"
    $path = "\\$($gpo.DomainName)\SYSVOL\$($gpo.DomainName)\Policies\$guid\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    if (-not (Test-Path $path)) {
        Write-Host "Arquivo de template de seguranca NAO encontrado em: $path" -ForegroundColor Yellow
        return $null
    }
    return Get-Content -Path $path -Encoding Unicode
}

function Get-IniValue {
    param($Linhas, [string]$Secao, [string]$Chave)
    if (-not $Linhas) { return $null }
    $dentro = $false
    foreach ($l in $Linhas) {
        if ($l -match '^\[(.+)\]\s*$') { $dentro = ($matches[1] -eq $Secao); continue }
        if ($dentro -and $l -match '^(.*?)\s*=\s*(.*)$') {
            if ($matches[1].Trim() -eq $Chave) { return $matches[2].Trim() }
        }
    }
    return $null
}

function Mostrar-Valor {
    param([string]$Label, $Valor)
    if ($null -eq $Valor -or $Valor -eq "") { $Valor = "NAO ENCONTRADO" }
    Write-Host ("  {0,-30}: {1}" -f $Label, $Valor)
}

# ---------------------------------------------------------------
# 1) GPOs existem?
# ---------------------------------------------------------------
Mostrar-Cabecalho "1) GPOs existentes"
$gposEsperadas = @("Default Domain Policy", "LAPS", "Restricted Groups")
foreach ($nome in $gposEsperadas) {
    try {
        $g = Get-GPO -Name $nome -ErrorAction Stop
        Write-Host "  OK  - '$nome' existe (Id: $($g.Id))" -ForegroundColor Green
    } catch {
        Write-Host "  FALTANDO - '$nome' nao foi encontrada" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------
# 2) Onde cada GPO esta vinculada
# ---------------------------------------------------------------
Mostrar-Cabecalho "2) Vinculos (links) de cada GPO"
foreach ($nome in $gposEsperadas) {
    try {
        [xml]$rel = Get-GPOReport -Name $nome -ReportType Xml -ErrorAction Stop
        if ($rel.GPO.LinksTo) {
            foreach ($link in $rel.GPO.LinksTo) {
                Write-Host ("  {0,-22} -> {1}" -f $nome, $link.SOMPath)
            }
        } else {
            Write-Host ("  {0,-22} -> NAO ESTA VINCULADA A NENHUMA OU/DOMINIO" -f $nome) -ForegroundColor Red
        }
    } catch {
        Write-Host "  $nome -> GPO nao encontrada, pulando." -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------
# 3) Senha / Bloqueio / Auditoria (Default Domain Policy)
# ---------------------------------------------------------------
Mostrar-Cabecalho "3) Senha, bloqueio e auditoria (arquivo da GPO 'Default Domain Policy')"
$linhasDefault = Ler-GptTmpl -GpoName "Default Domain Policy"
if ($linhasDefault) {
    Mostrar-Valor "Tamanho minimo senha"    (Get-IniValue $linhasDefault "System Access" "MinimumPasswordLength")
    Mostrar-Valor "Complexidade (1=ativa)"  (Get-IniValue $linhasDefault "System Access" "PasswordComplexity")
    Mostrar-Valor "Validade maxima (dias)"  (Get-IniValue $linhasDefault "System Access" "MaximumPasswordAge")
    Mostrar-Valor "Historico de senhas"     (Get-IniValue $linhasDefault "System Access" "PasswordHistorySize")
    Mostrar-Valor "Tentativas p/ bloqueio"  (Get-IniValue $linhasDefault "System Access" "LockoutBadCount")
    Mostrar-Valor "Duracao bloqueio (min)"  (Get-IniValue $linhasDefault "System Access" "LockoutDuration")
    Mostrar-Valor "Reset contador (min)"    (Get-IniValue $linhasDefault "System Access" "ResetLockoutCount")

    $auditLogon = Get-IniValue $linhasDefault "Event Audit" "AuditAccountLogon"
    $auditEvent = Get-IniValue $linhasDefault "Event Audit" "AuditLogonEvents"
    Mostrar-Valor "AuditAccountLogon (3=S+F)" $auditLogon
    Mostrar-Valor "AuditLogonEvents (3=S+F)"  $auditEvent
}

Write-Host "`n  --- Confirmando pela politica EFETIVA do dominio (fonte oficial) ---" -ForegroundColor DarkCyan
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, ComplexityEnabled, MaxPasswordAge, PasswordHistoryCount, LockoutThreshold, LockoutDuration, LockoutObservationWindow

# ---------------------------------------------------------------
# 4) Redirecionamento do container de computadores
# ---------------------------------------------------------------
Mostrar-Cabecalho "4) Redirecionamento de computadores novos"
$containerAtual = (Get-ADDomain).ComputersContainer
Write-Host "  Container atual (onde PCs novos caem): $containerAtual"
if ($containerAtual -like "CN=Computers,*") {
    Write-Host "  ATENCAO: ainda esta no padrao (CN=Computers) - redirecionamento pode nao ter sido aplicado." -ForegroundColor Yellow
} else {
    Write-Host "  OK - redirecionado para uma OU customizada." -ForegroundColor Green
}

# ---------------------------------------------------------------
# 5) LAPS
# ---------------------------------------------------------------
Mostrar-Cabecalho "5) Configuracoes do LAPS (GPO 'LAPS')"
$chaveLaps = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valoresLaps = @("BackupDirectory","PasswordComplexity","PasswordLength","PasswordAgeDays","ADPasswordEncryptionEnabled","PasswordHistorySize","PostAuthenticationActions","PostAuthenticationResetDelay","AdministratorAccountName")
foreach ($v in $valoresLaps) {
    try {
        $r = Get-GPRegistryValue -Name "LAPS" -Key $chaveLaps -ValueName $v -ErrorAction Stop
        Mostrar-Valor $v $r.Value
    } catch {
        Mostrar-Valor $v "(nao configurado)"
    }
}
$linhasLaps = Ler-GptTmpl -GpoName "LAPS"
if ($linhasLaps) {
    Mostrar-Valor "EnableAdminAccount" (Get-IniValue $linhasLaps "System Access" "EnableAdminAccount")
}

Write-Host "`n  --- Schema do LAPS estendido? ---" -ForegroundColor DarkCyan
try {
    $schemaOk = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter "Name -eq 'ms-LAPS-Password'" -ErrorAction Stop
    if ($schemaOk) { Write-Host "  OK - atributo ms-LAPS-Password existe no schema." -ForegroundColor Green }
    else { Write-Host "  NAO ENCONTRADO - schema pode nao ter sido estendido." -ForegroundColor Red }
} catch {
    Write-Host "  Nao foi possivel checar o schema." -ForegroundColor Yellow
}

# ---------------------------------------------------------------
# 6) Restricted Groups
# ---------------------------------------------------------------
Mostrar-Cabecalho "6) Restricted Groups (GPO 'Restricted Groups')"
$linhasRestricted = Ler-GptTmpl -GpoName "Restricted Groups"
if ($linhasRestricted) {
    $membros = Get-IniValue $linhasRestricted "Group Membership" "*S-1-5-32-544__Members"
    Mostrar-Valor "Administradores locais definidos" $membros
}

Write-Host "`n===================== VALIDACAO FINALIZADA =====================" -ForegroundColor Cyan
Write-Host "Obs.: isso confirma o que esta gravado no AD/SYSVOL. Para confirmar" -ForegroundColor DarkGray
Write-Host "que uma maquina especifica ja aplicou, rode gpupdate /force nela e" -ForegroundColor DarkGray
Write-Host "depois gpresult /r ou os testes especificos (net accounts, etc)." -ForegroundColor DarkGray

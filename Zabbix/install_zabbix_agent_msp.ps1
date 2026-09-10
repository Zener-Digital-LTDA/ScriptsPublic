# ===============================
# Zabbix Agent2 MSP Auto Deploy
# ===============================
param(
    [string]$ZabbixServer = ""
)
$ScriptsPath    = "C:\Scripts"
$AgentFolder    = "C:\Program Files\Zabbix Agent 2"
$ConfigPath     = "$AgentFolder\zabbix_agent2.conf"
$DeployLog      = "C:\Scripts\zabbix_deploy.log"
$GitUpdateScript      = "https://raw.githubusercontent.com/MarceloRC/Zabbix-Install/main/windows_update_check.ps1"
$GitADScript          = "https://raw.githubusercontent.com/MarceloRC/Zabbix-Install/main/ad_replication.ps1"
$GitRDSScript         = "https://raw.githubusercontent.com/MarceloRC/Zabbix-Install/main/rds_grace.ps1"
$GitADSecurityScript  = "https://raw.githubusercontent.com/MarceloRC/Zabbix-Install/main/ad_security_check.ps1"
$GitADUserInvScript   = "https://raw.githubusercontent.com/MarceloRC/Zabbix-Install/main/ad_user_inventory.ps1"
$AgentURL        = "https://cdn.zabbix.com/zabbix/binaries/stable/7.0/7.0.23/zabbix_agent2-7.0.23-windows-amd64-openssl.msi"
$AgentInstaller  = "C:\Scripts\zabbix_agent2.msi"
# =========================
# FUNCAO DE LOG
# =========================
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    Write-Host $line
    Add-Content -Path $DeployLog -Value $line -Encoding UTF8
}
# =========================
# VERIFICAR ADMINISTRADOR
# =========================
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERRO: Execute este script como Administrador." -ForegroundColor Red
    exit 1
}
# =========================
# CRIAR PASTA SCRIPTS
# =========================
if (!(Test-Path $ScriptsPath)) {
    New-Item -ItemType Directory -Path $ScriptsPath | Out-Null
}
Write-Log "===== ZABBIX MSP INSTALL INICIADO ====="
Write-Log "Computador: $env:COMPUTERNAME"
Write-Log "Usuario: $env:USERNAME"
# =========================
# DETECTAR GATEWAY / ZABBIX SERVER
# =========================
if ($ZabbixServer -ne "") {
    $Gateway = $ZabbixServer
    Write-Log "Zabbix Server definido via parametro: $Gateway"
} else {
    $DetectedGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
        Sort-Object RouteMetric |
        Select-Object -First 1).NextHop
    Write-Log "Gateway detectado: $DetectedGateway"
    $UseDetected = Read-Host "Usar este gateway como Zabbix Server? (Y/N)"
    if ($UseDetected -eq "N" -or $UseDetected -eq "n") {
        $Gateway = Read-Host "Digite o IP do Zabbix Server"
    } else {
        $Gateway = $DetectedGateway
    }
}
Write-Log "Zabbix Server configurado como: $Gateway"
# =========================
# HOSTNAME
# =========================
$hostname = $env:COMPUTERNAME
$domain   = (Get-CimInstance Win32_ComputerSystem).Domain
if ($domain -and $domain -ne $hostname) {
    $fqdn = "$hostname.$domain"
} else {
    $fqdn = $hostname
}
Write-Log "Hostname: $fqdn"
# =========================
# DETECTAR ROLES AUTOMATICAMENTE
# =========================
Write-Log "Detectando roles do servidor..."
$IsDC = $false
$IsTS = $false
try {
    $adFeature  = Get-WindowsFeature AD-Domain-Services -ErrorAction Stop
    $rdsFeature = Get-WindowsFeature RDS-RD-Server -ErrorAction Stop
    if ($adFeature.InstallState -eq "Installed") {
        $IsDC = $true
        Write-Log "Role detectada: Domain Controller (AD-Domain-Services)"
    }
    if ($rdsFeature.InstallState -eq "Installed") {
        $IsTS = $true
        Write-Log "Role detectada: Terminal Server / RDS (RDS-RD-Server)"
    }
} catch {
    Write-Log "AVISO: Nao foi possivel detectar roles via Get-WindowsFeature. ($($_.Exception.Message))"
}
if (-not $IsDC -and -not $IsTS) {
    Write-Log "Servidor identificado como: Membro comum (sem DC ou RDS)"
}
# =========================
# BAIXAR AGENT
# =========================
Write-Log "Baixando Zabbix Agent..."
try {
    Invoke-WebRequest $AgentURL -OutFile $AgentInstaller -ErrorAction Stop
    Write-Log "Download concluido: $AgentInstaller"
} catch {
    Write-Log "ERRO no download do Agent: $($_.Exception.Message)"
    exit 1
}
# =========================
# LIMPEZA COMPLETA
# =========================
Write-Log "========== INICIANDO LIMPEZA COMPLETA ZABBIX =========="
# PASSO 1: Desinstalar via MSI
$zabbixInstalled = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Zabbix Agent*" }
if ($zabbixInstalled) {
    foreach ($app in $zabbixInstalled) {
        $productCode = $app.PSChildName
        Write-Log "Desinstalando versao anterior: $($app.DisplayName) $($app.DisplayVersion)"
        Start-Process "msiexec.exe" -Wait -ArgumentList "/x `"$productCode`" /qn /norestart" -ErrorAction SilentlyContinue
    }
    Start-Sleep 3
}
# PASSO 2: Limpar flag de reboot pendente
$pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$pending = Get-ItemProperty $pendingKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
if ($pending) {
    Remove-ItemProperty $pendingKey -Name "PendingFileRenameOperations" -Force -ErrorAction SilentlyContinue
    Write-Log "Flag de reboot pendente removido."
}
# PASSO 3: Parar e remover servicos restantes
$services = @("Zabbix Agent", "Zabbix Agent 2")
foreach ($svc in $services) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete "$svc" | Out-Null
        Write-Log "Servico removido: $svc"
    }
}
# PASSO 4: Remover chaves de registro restantes
$serviceRegPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\Zabbix Agent",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Zabbix Agent 2",
    "HKLM:\SYSTEM\ControlSet001\Services\Zabbix Agent",
    "HKLM:\SYSTEM\ControlSet001\Services\Zabbix Agent 2",
    "HKLM:\SYSTEM\ControlSet002\Services\Zabbix Agent",
    "HKLM:\SYSTEM\ControlSet002\Services\Zabbix Agent 2"
)
foreach ($path in $serviceRegPaths) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
$eventPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Zabbix Agent",
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Zabbix Agent 2",
    "HKLM:\SYSTEM\ControlSet001\Services\EventLog\Application\Zabbix Agent",
    "HKLM:\SYSTEM\ControlSet001\Services\EventLog\Application\Zabbix Agent 2",
    "HKLM:\SYSTEM\ControlSet002\Services\EventLog\Application\Zabbix Agent",
    "HKLM:\SYSTEM\ControlSet002\Services\EventLog\Application\Zabbix Agent 2"
)
foreach ($path in $eventPaths) {
    if (Test-Path $path) {
        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
# PASSO 5: Remover pastas restantes
$oldPaths = @(
    "C:\Program Files\Zabbix Agent",
    "C:\Program Files\Zabbix Agent 2",
    "C:\Program Files (x86)\Zabbix Agent",
    "C:\Program Files (x86)\Zabbix Agent 2"
)
foreach ($p in $oldPaths) {
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Pasta removida: $p"
    }
}
Write-Log "========== LIMPEZA FINALIZADA =========="
# =========================
# INSTALACAO
# =========================
Write-Log "Instalando Agent..."
Unblock-File $AgentInstaller
$msiLog = "C:\Scripts\zabbix_install.log"
$msiResult = Start-Process "msiexec.exe" -Wait -PassThru -ArgumentList @(
    "/i", "`"$AgentInstaller`"",
    "/qn", "/norestart",
    "/l*v", "`"$msiLog`"",
    "SERVER=$Gateway",
    "SERVERACTIVE=$Gateway",
    "HOSTNAME=$fqdn"
)
Write-Log "msiexec ExitCode: $($msiResult.ExitCode)"
if ($msiResult.ExitCode -ne 0) {
    Write-Log "ERRO na instalacao. Veja o log em: $msiLog"
    exit 1
}
# Aguardar pasta ser criada pelo instalador (ate 30s)
$timeout = 30
$elapsed = 0
while (!(Test-Path $AgentFolder) -and $elapsed -lt $timeout) {
    Start-Sleep 2
    $elapsed += 2
}
if (!(Test-Path $AgentFolder)) {
    Write-Log "ERRO: Pasta do Agent nao foi criada. Verifique o instalador."
    exit 1
}
# =========================
# FIREWALL - PORTA 10050
# =========================
Write-Log "Configurando regra de Firewall (porta 10050)..."
$fwRule = Get-NetFirewallRule -DisplayName "Zabbix Agent" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule `
        -DisplayName "Zabbix Agent" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 10050 `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Log "Regra de firewall criada: porta 10050 liberada."
} else {
    Write-Log "Regra de firewall ja existia, sem alteracoes."
}
# =========================
# CONFIGURACAO BASE
# =========================
if (Test-Path $ConfigPath) {
    Copy-Item $ConfigPath "$ConfigPath.bak" -Force
    Write-Log "Backup do config anterior salvo em: $ConfigPath.bak"
}
Write-Log "Baixando scripts auxiliares do GitHub..."
Invoke-WebRequest $GitUpdateScript     -OutFile "$ScriptsPath\windows_update_check.ps1"
Invoke-WebRequest $GitADScript         -OutFile "$ScriptsPath\ad_replication.ps1"
Invoke-WebRequest $GitRDSScript        -OutFile "$ScriptsPath\rds_grace.ps1"
Invoke-WebRequest $GitADSecurityScript -OutFile "$ScriptsPath\ad_security_check.ps1"
Invoke-WebRequest $GitADUserInvScript  -OutFile "$ScriptsPath\ad_user_inventory.ps1"
$config = @"
LogFile=C:\Program Files\Zabbix Agent 2\zabbix_agent2.log
Server=$Gateway
Hostname=$fqdn
ControlSocket=\\.\pipe\agent.sock
UnsafeUserParameters=1
Include=.\zabbix_agent2.d\plugins.d\*.conf
UserParameter=windows.update.total,powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content C:\Scripts\windows_update_status.txt | Select-String 'TotalUpdates').ToString().Split('=')[1]"
UserParameter=windows.update.critical,powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content C:\Scripts\windows_update_status.txt | Select-String 'CriticalUpdates').ToString().Split('=')[1]"
UserParameter=windows.update.security,powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content C:\Scripts\windows_update_status.txt | Select-String 'SecurityUpdates').ToString().Split('=')[1]"
UserParameter=windows.update.reboot,powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content C:\Scripts\windows_update_status.txt | Select-String 'RebootRequired').ToString().Split('=')[1]"
UserParameter=windows.update.service,powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content C:\Scripts\windows_update_status.txt | Select-String 'WUServiceRunning').ToString().Split('=')[1]"
UserParameter=windows.update.days,powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content C:\Scripts\windows_update_status.txt | Select-String 'DaysSinceLastUpdate').ToString().Split('=')[1]"
"@
$config | Out-File -Encoding ascii $ConfigPath
Write-Log "Configuracao base aplicada."
# =========================
# RDS / TERMINAL SERVER (automatico)
# =========================
if ($IsTS) {
    $rdsParam = "UserParameter=rds.gracedays,type C:\Scripts\rds_grace.txt"
    Add-Content -Path $ConfigPath -Value $rdsParam -Encoding ASCII
    Write-Log "Configuracao RDS adicionada ao config."

    Write-Log "Executando verificacao inicial de RDS Grace Period..."
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\rds_grace.ps1"

    Write-Log "Criando task 'Zabbix-RDS-Grace-Check' (diaria as 06:00)..."
    $RDSAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\rds_grace.ps1"
    $RDSTrigger = New-ScheduledTaskTrigger -Daily -At 06:00
    $RDSPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    Register-ScheduledTask `
        -TaskName "Zabbix-RDS-Grace-Check" `
        -Action $RDSAction `
        -Trigger $RDSTrigger `
        -Principal $RDSPrincipal `
        -Force | Out-Null
    Write-Log "Task 'Zabbix-RDS-Grace-Check' criada com sucesso."
}
# =========================
# DOMAIN CONTROLLER (automatico)
# =========================
if ($IsDC) {
    # ---- AD Replication (ja existente) ----
    $adParam = "UserParameter=ad.replication.status,powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"Get-Content C:\Scripts\ad_result.txt`""
    Add-Content -Path $ConfigPath -Value $adParam -Encoding ASCII
    Write-Log "Configuracao AD Replication adicionada ao config."
    $ADAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\ad_replication.ps1"
    $ADTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) -Once -At (Get-Date)
    $ADPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    Register-ScheduledTask `
        -TaskName "Zabbix-AD-Replication-Check" `
        -Action $ADAction `
        -Trigger $ADTrigger `
        -Principal $ADPrincipal `
        -Force | Out-Null
    Write-Log "Task 'Zabbix-AD-Replication-Check' criada (a cada 30 minutos)."
    Write-Log "Executando verificacao inicial de replicacao AD..."
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\ad_replication.ps1"

    # ---- AD Security Check (novo) ----
    $adSecParams = @(
        "UserParameter=ad.security.stale,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'StaleAccounts').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.pwneverexpires,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'PasswordNeverExpires').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.kerberoastable,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'KerberoastableAccounts').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.domainadmins,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'DomainAdminsCount').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.enterpriseadmins,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'EnterpriseAdminsCount').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.protectedusers,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'ProtectedUsersCount').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.unconstraineddeleg,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'UnconstrainedDelegation').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.trusts,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'TrustsCount').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.obsoleteos,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'ObsoleteOS').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.laps,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'LAPSImplemented').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.guestenabled,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'GuestEnabled').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.smb1enabled,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'SMB1Enabled').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.reversibleenc,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'ReversibleEncryptionAccounts').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.prewin2000,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'PreWin2000CompatMembers').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.recyclebin,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'RecycleBinEnabled').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.pwnotrequired,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'PasswordNotRequiredAccounts').ToString().Split('=')[1]`"",
        "UserParameter=ad.security.errorflag,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_security_status.txt | Select-String 'ErrorFlag').ToString().Split('=')[1]`""
    )
    foreach ($line in $adSecParams) {
        Add-Content -Path $ConfigPath -Value $line -Encoding ASCII
    }
    Write-Log "Configuracao AD Security Check adicionada ao config."

    Write-Log "Executando verificacao inicial de AD Security Check..."
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\ad_security_check.ps1"

    Write-Log "Criando task 'Zabbix-AD-Security-Check' (diaria as 06:00)..."
    $ADSecAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\ad_security_check.ps1"
    $ADSecTrigger = New-ScheduledTaskTrigger -Daily -At 06:00
    $ADSecPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    Register-ScheduledTask `
        -TaskName "Zabbix-AD-Security-Check" `
        -Action $ADSecAction `
        -Trigger $ADSecTrigger `
        -Principal $ADSecPrincipal `
        -Force | Out-Null
    Write-Log "Task 'Zabbix-AD-Security-Check' criada com sucesso."

    # ---- AD User Inventory (novo) ----
    $adUserInvParams = @(
        "UserParameter=ad.user.total,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^TotalUsers=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.active,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^ActiveUsers=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.disabled,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^DisabledUsers=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.serviceaccounts,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^ServiceAccounts=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.serviceaccounts.pwdneverexpires,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^ServiceAccountsPwdNeverExpires=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.disabledover90d,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^DisabledOver90Days=').ToString().Split('=')[1]`"",
        "UserParameter=ad.computers.total,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^ComputersTotal=').ToString().Split('=')[1]`"",
        "UserParameter=ad.computers.stale90d,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^ComputersStale90d=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.errorflag,powershell -NoProfile -ExecutionPolicy Bypass -Command `"(Get-Content C:\Scripts\ad_user_inventory_status.txt | Select-String '^ErrorFlag=').ToString().Split('=')[1]`"",
        "UserParameter=ad.user.dept.data,type C:\Scripts\ad_user_departments.json"
    )
    foreach ($line in $adUserInvParams) {
        Add-Content -Path $ConfigPath -Value $line -Encoding ASCII
    }
    Write-Log "Configuracao AD User Inventory adicionada ao config."

    Write-Log "Executando verificacao inicial de AD User Inventory..."
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\ad_user_inventory.ps1"

    Write-Log "Criando task 'Zabbix-AD-User-Inventory-Check' (diaria as 06:00)..."
    $ADUserInvAction = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\ad_user_inventory.ps1"
    $ADUserInvTrigger = New-ScheduledTaskTrigger -Daily -At 06:00
    $ADUserInvPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    Register-ScheduledTask `
        -TaskName "Zabbix-AD-User-Inventory-Check" `
        -Action $ADUserInvAction `
        -Trigger $ADUserInvTrigger `
        -Principal $ADUserInvPrincipal `
        -Force | Out-Null
    Write-Log "Task 'Zabbix-AD-User-Inventory-Check' criada com sucesso."
}
# =========================
# SERVICO
# =========================
$serviceName = "Zabbix Agent 2"
$exePath     = "C:\Program Files\Zabbix Agent 2\zabbix_agent2.exe"
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Log "Servico ja existe, reiniciando..."
    Restart-Service $serviceName -Force
} else {
    Write-Log "Servico nao encontrado, criando manualmente..."
    if (Test-Path $exePath) {
        & "$exePath" --config "$ConfigPath" --install
        Start-Sleep 2
        Start-Service $serviceName
        Write-Log "Servico criado e iniciado."
    } else {
        Write-Log "ERRO: Executavel nao encontrado em $exePath"
    }
}
# =========================
# EXECUTAR CHECK DE UPDATES
# =========================
Write-Log "Executando verificacao inicial de Windows Update..."
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\windows_update_check.ps1"
# =========================
# TASK AGENDADA - WINDOWS UPDATE (automatica)
# =========================
Write-Log "Criando task 'Zabbix-Windows-Update-Check'..."
$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\windows_update_check.ps1"
$Trigger1 = New-ScheduledTaskTrigger -Daily -At 13:00
$Trigger2 = New-ScheduledTaskTrigger -Daily -At 03:00
$Trigger3 = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest
Register-ScheduledTask `
    -TaskName "Zabbix-Windows-Update-Check" `
    -Action $Action `
    -Trigger @($Trigger1, $Trigger2, $Trigger3) `
    -Principal $Principal `
    -Force | Out-Null
Write-Log "Task 'Zabbix-Windows-Update-Check' criada com sucesso."
# =========================
# VERIFICACAO POS-INSTALL
# =========================
Write-Log "========== VERIFICACAO POS-INSTALL =========="
$svcFinal = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svcFinal -and $svcFinal.Status -eq "Running") {
    Write-Log "OK - Servico '$serviceName' esta RODANDO."
} else {
    Write-Log "ATENCAO - Servico '$serviceName' NAO esta rodando. Status: $($svcFinal.Status)"
}
Write-Log "Testando conectividade com Zabbix Server ($Gateway):10051..."
$connTest = Test-NetConnection -ComputerName $Gateway -Port 10051 -WarningAction SilentlyContinue
if ($connTest.TcpTestSucceeded) {
    Write-Log "OK - Porta 10051 acessivel no Zabbix Server."
} else {
    Write-Log "ATENCAO - Porta 10051 NAO acessivel em $Gateway. Verifique firewall/roteamento."
}
Write-Log "========== DEPLOY FINALIZADO =========="
Write-Log "Log completo salvo em: $DeployLog"
Write-Host ""
Write-Host "ZABBIX AGENT INSTALADO E CONFIGURADO" -ForegroundColor Green

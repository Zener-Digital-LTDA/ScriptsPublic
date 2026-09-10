# ============================================================
# ad_security_check.ps1
# Auditoria de seguranca do Active Directory para Zabbix
# (equivalente simplificado a indicadores do PingCastle,
#  100% nativo via PowerShell / RSAT-AD-PowerShell)
#
# Execucao: Task Scheduler (recomendado 1x/dia, ex: 06:00)
# Resultado salvo em: C:\Scripts\ad_security_status.txt
#
# Formato do arquivo (KEY=VALUE por linha):
#   StaleAccounts=NN
#   PasswordNeverExpires=NN
#   KerberoastableAccounts=NN
#   DomainAdminsCount=NN
#   EnterpriseAdminsCount=NN
#   ProtectedUsersCount=NN
#   UnconstrainedDelegation=NN
#   TrustsCount=NN
#   ObsoleteOS=NN
#   LAPSImplemented=1|0
#   GuestEnabled=1|0
#   SMB1Enabled=1|0
#   ReversibleEncryptionAccounts=NN
#   PreWin2000CompatMembers=NN
#   RecycleBinEnabled=1|0
#   PasswordNotRequiredAccounts=NN
#   ErrorFlag=0|1   (1 = algum modulo falhou ao coletar)
# ============================================================
$statusFile = "C:\Scripts\ad_security_status.txt"
$results = [ordered]@{
    StaleAccounts                = -1
    PasswordNeverExpires         = -1
    KerberoastableAccounts       = -1
    DomainAdminsCount            = -1
    EnterpriseAdminsCount        = -1
    ProtectedUsersCount          = -1
    UnconstrainedDelegation      = -1
    TrustsCount                  = -1
    ObsoleteOS                   = -1
    LAPSImplemented              = -1
    GuestEnabled                 = -1
    SMB1Enabled                  = -1
    ReversibleEncryptionAccounts = -1
    PreWin2000CompatMembers      = -1
    RecycleBinEnabled            = -1
    PasswordNotRequiredAccounts  = -1
    ErrorFlag                    = 0
}
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not (Get-Module ActiveDirectory)) {
    # Modulo AD nao disponivel, grava tudo como erro e sai
    $results.ErrorFlag = 1
    $lines = foreach ($key in $results.Keys) { "$key=$($results[$key])" }
    $lines | Out-File -FilePath $statusFile -Encoding ASCII
    exit 1
}
$domain = (Get-ADDomain).DNSRoot
# ---- 1. Contas inativas (90+ dias sem logon) ----------------
try {
    $stale = Search-ADAccount -AccountInactive -TimeSpan "90.00:00:00" -UsersOnly -ErrorAction Stop |
        Where-Object { $_.Enabled -eq $true }
    $results.StaleAccounts = ($stale | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 2. Contas com senha configurada para nunca expirar -----
try {
    $neverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -ErrorAction Stop
    $results.PasswordNeverExpires = ($neverExpires | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 3. Contas kerberoastable (SPN setado, usuario ativo) ---
try {
    $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" -and Enabled -eq $true } `
        -Properties ServicePrincipalName -ErrorAction Stop
    $results.KerberoastableAccounts = ($spnUsers | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 4. Membros de Domain Admins ----------------------------
try {
    $da = Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction Stop
    $results.DomainAdminsCount = ($da | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 5. Membros de Enterprise Admins (so existe na root do forest) ----
try {
    $ea = Get-ADGroupMember "Enterprise Admins" -Recursive -ErrorAction Stop
    $results.EnterpriseAdminsCount = ($ea | Measure-Object).Count
} catch {
    # Normal falhar se o DC nao for da forest root; nao marca ErrorFlag
    $results.EnterpriseAdminsCount = 0
}
# ---- 6. Membros do grupo Protected Users --------------------
try {
    $pu = Get-ADGroupMember "Protected Users" -Recursive -ErrorAction Stop
    $results.ProtectedUsersCount = ($pu | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 7. Unconstrained Delegation (usuarios e computadores) --
#          Domain Controllers SEMPRE tem TrustedForDelegation=True por
#          design do Kerberos (isso e obrigatorio para o funcionamento
#          do AD, nao e uma falha de configuracao). Por isso excluimos
#          qualquer objeto computador cujo PrimaryGroupID seja 516
#          (RID fixo do grupo "Domain Controllers"), em vez de comparar
#          apenas com o hostname local — assim o filtro cobre todos os
#          DCs da floresta, nao so o servidor onde o script roda.
try {
    $delegUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true } -ErrorAction Stop

    $delegComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
        -Properties PrimaryGroupID -ErrorAction Stop |
        Where-Object { $_.PrimaryGroupID -ne 516 } # exclui qualquer Domain Controller da floresta

    $results.UnconstrainedDelegation = ($delegUsers | Measure-Object).Count + ($delegComputers | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 8. Quantidade de Trusts ---------------------------------
try {
    $trusts = Get-ADTrust -Filter * -ErrorAction Stop
    $results.TrustsCount = ($trusts | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 9. Computadores com SO obsoleto (fora de suporte) ------
try {
    $obsoleteOS = @(
        "Windows 2000*", "Windows XP*", "Windows Vista*",
        "Windows Server 2003*", "Windows Server 2008*", "Windows Server 2008 R2*",
        "Windows 7*", "Windows Server 2012*", "Windows 8*"
    )
    $allComputers = Get-ADComputer -Filter { Enabled -eq $true } -Properties OperatingSystem -ErrorAction Stop
    $obsolete = $allComputers | Where-Object {
        $os = $_.OperatingSystem
        if (-not $os) { return $false }
        foreach ($pattern in $obsoleteOS) {
            if ($os -like $pattern) { return $true }
        }
        return $false
    }
    $results.ObsoleteOS = ($obsolete | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 10. LAPS implementado (schema tem o atributo) ----------
#          Cobre LAPS legado (ms-Mcs-AdmPwd) e Windows LAPS nativo.
#          IMPORTANTE: no Windows LAPS nativo, o "Name"/cn do atributo no schema
#          e "ms-LAPS-Password" (com hifen), mas o lDAPDisplayName e "msLAPS-Password"
#          (sem hifen antes de LAPS). Por isso filtramos por lDAPDisplayName, que e
#          o identificador estavel, em vez de Name.
try {
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    $lapsAttrs = Get-ADObject -SearchBase $rootDSE.schemaNamingContext `
        -LDAPFilter "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))" -ErrorAction Stop
    if ($lapsAttrs) {
        $results.LAPSImplemented = 1
    } else {
        $results.LAPSImplemented = 0
    }
} catch {
    $results.LAPSImplemented = 0
}
# ---- 11. Conta Guest habilitada ------------------------------
try {
    $guest = Get-ADUser -Identity "Guest" -Properties Enabled -ErrorAction Stop
    $results.GuestEnabled = [int]$guest.Enabled
} catch {
    $results.ErrorFlag = 1
}
# ---- 12. SMBv1 habilitado no servidor ------------------------
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
    $results.SMB1Enabled = if ($smb1.State -eq "Enabled") { 1 } else { 0 }
} catch {
    # Alguns SOs nao expoem essa feature via este cmdlet; nao marca ErrorFlag geral
    $results.SMB1Enabled = 0
}
# ---- 13. Contas com Reversible Encryption habilitado --------
try {
    $revEnc = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true } -ErrorAction Stop
    $results.ReversibleEncryptionAccounts = ($revEnc | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 14. Membros do grupo "Pre-Windows 2000 Compatible Access" ----
try {
    $preWin2000 = Get-ADGroupMember "Pre-Windows 2000 Compatible Access" -ErrorAction Stop
    $results.PreWin2000CompatMembers = ($preWin2000 | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- 15. AD Recycle Bin habilitado ---------------------------
try {
    $recycleBin = Get-ADOptionalFeature -Filter { Name -eq "Recycle Bin Feature" } -ErrorAction Stop
    if ($recycleBin.EnabledScopes -and $recycleBin.EnabledScopes.Count -gt 0) {
        $results.RecycleBinEnabled = 1
    } else {
        $results.RecycleBinEnabled = 0
    }
} catch {
    $results.ErrorFlag = 1
}
# ---- 16. Contas com PasswordNotRequired ----------------------
try {
    $noPwdReq = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } -ErrorAction Stop
    $results.PasswordNotRequiredAccounts = ($noPwdReq | Measure-Object).Count
} catch {
    $results.ErrorFlag = 1
}
# ---- Gravar resultado ----------------------------------------
$lines = foreach ($key in $results.Keys) { "$key=$($results[$key])" }
$lines | Out-File -FilePath $statusFile -Encoding ASCII
if ($results.ErrorFlag -eq 1) { exit 2 } else { exit 0 }

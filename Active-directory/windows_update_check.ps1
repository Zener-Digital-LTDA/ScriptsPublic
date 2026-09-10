$ErrorActionPreference = "SilentlyContinue"
$output = "C:\Scripts\windows_update_status.txt"

if (-not (Test-Path "C:\Scripts")) {
    New-Item -ItemType Directory -Path "C:\Scripts" | Out-Null
}

# --- Updates pendentes via COM ---
$total = 0; $critical = 0; $security = 0
try {
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult   = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    foreach ($update in $SearchResult.Updates) {
        $total++
        if ($update.MsrcSeverity -eq "Critical") { $critical++ }
        foreach ($cat in $update.Categories) {
            if ($cat.Name -eq "Security Updates") { $security++ }
        }
    }
} catch { }

# --- Reboot pendente (3 locais) ---
$reboot = 0
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $reboot = 1 }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")  { $reboot = 1 }
$pfro = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue
if ($pfro.PendingFileRenameOperations) { $reboot = 1 }

# --- Servico WU ---
$svc = Get-Service wuauserv -ErrorAction SilentlyContinue
$service_status = if ($svc.Status -eq "Running") { 1 } else { 0 }

# --- Dias desde ultimo update (via Event Log - mais confiavel no 2019 Core) ---
$days_since_update = 999
$lastEvent = Get-WinEvent -LogName "System" -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 19 -and $_.ProviderName -eq "Microsoft-Windows-WindowsUpdateClient" } |
    Select-Object -First 1   # ja vem ordenado do mais recente

if ($lastEvent) {
    $days_since_update = (New-TimeSpan -Start $lastEvent.TimeCreated -End (Get-Date)).Days
}

# --- Fallback: CBS log (se Event Log nao retornar) ---
if ($days_since_update -eq 999) {
    $cbsLog = "C:\Windows\Logs\CBS\CBS.log"
    if (Test-Path $cbsLog) {
        $days_since_update = (New-TimeSpan -Start (Get-Item $cbsLog).LastWriteTime -End (Get-Date)).Days
    }
}

# --- Grava arquivo ---
"TotalUpdates=$total"                    | Out-File $output -Encoding UTF8
"CriticalUpdates=$critical"              | Out-File $output -Encoding UTF8 -Append
"SecurityUpdates=$security"              | Out-File $output -Encoding UTF8 -Append
"RebootRequired=$reboot"                 | Out-File $output -Encoding UTF8 -Append
"WUServiceRunning=$service_status"       | Out-File $output -Encoding UTF8 -Append
"DaysSinceLastUpdate=$days_since_update" | Out-File $output -Encoding UTF8 -Append

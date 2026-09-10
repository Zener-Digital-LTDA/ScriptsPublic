# C:\Scripts\rds_grace.ps1
$dias = (Invoke-CimMethod -InputObject (Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TerminalServiceSetting) -MethodName GetGracePeriodDays).DaysLeft
$dias | Out-File -FilePath "C:\Scripts\rds_grace.txt" -Encoding ASCII -NoNewline

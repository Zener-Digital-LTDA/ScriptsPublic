# ============================================================
# ad_replication.ps1
# Validacao de integridade do Active Directory para Zabbix
# Execucao: Task Scheduler a cada 30 minutos
# Resultado salvo em C:\Scripts\ad_result.txt
#
# Codigos de retorno:
#   0 = Tudo OK
#   1 = Falha de replicacao AD (repadmin)
#   2 = Erro operacional / RPC / latencia
#   3 = DC com problema detectado pelo dcdiag
#   4 = SYSVOL nao compartilhado
#   5 = Policies sem conteudo no SYSVOL
# ============================================================

$resultFile = "C:\Scripts\ad_result.txt"

# ---- 1. Replicacao AD (repadmin /replsummary) ---------------
try {
    $replLines = repadmin /replsummary 2>&1
    $hasReplError = $false
    foreach ($line in $replLines) {
        if ($line -match "^\s+\S+\s+(\d+)\s*/\s*\d+") {
            if ([int]$matches[1] -gt 0) {
                $hasReplError = $true
                break
            }
        }
    }
    if ($hasReplError) {
        1 | Out-File $resultFile -NoNewline
        exit
    }
} catch {
    1 | Out-File $resultFile -NoNewline
    exit
}

# ---- 2. Erros operacionais / RPC / latencia -----------------
try {
    $replStr  = $replLines | Out-String
    $showrepl = repadmin /showrepl 2>&1 | Out-String
    $hasOpError = (
        $replStr  -match "operational error|RPC Server Unavailable|error 58" -or
        $showrepl -match "consecutivefailures\s*:\s*[1-9]" -or
        $showrepl -match "Last attempt.*failed"
    )
    if ($hasOpError) {
        2 | Out-File $resultFile -NoNewline
        exit
    }
} catch {
    2 | Out-File $resultFile -NoNewline
    exit
}

# ---- 3. Saude do DC (dcdiag) --------------------------------
try {
    $dcdiag = dcdiag /test:advertising /test:netlogons /test:dns /test:replications 2>&1 | Out-String
    if ($dcdiag -match "failed|FAIL") {
        3 | Out-File $resultFile -NoNewline
        exit
    }
} catch {
    3 | Out-File $resultFile -NoNewline
    exit
}

# ---- 4. SYSVOL compartilhado --------------------------------
try {
    $shares = net share 2>&1 | Out-String
    if ($shares -notmatch "SYSVOL") {
        4 | Out-File $resultFile -NoNewline
        exit
    }
} catch {
    4 | Out-File $resultFile -NoNewline
    exit
}

# ---- 5. Verificar se Policies tem conteudo no SYSVOL -------
$domain   = (Get-ADDomain).DNSRoot
$policies = Get-ChildItem "C:\WINDOWS\SYSVOL\sysvol\$domain\Policies" -ErrorAction SilentlyContinue
if ($null -eq $policies -or $policies.Count -eq 0) {
    5 | Out-File $resultFile -NoNewline
    exit
}

# ---- Tudo OK ------------------------------------------------
0 | Out-File $resultFile -NoNewline

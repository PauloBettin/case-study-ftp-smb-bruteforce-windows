# Script Fail2Ban para Windows: FTP + SMB
# Monitora logs do IIS FTP e eventos de falha de logon (4625)
# Bloqueia IPs automaticamente via Windows Firewall
# Inclui registro em arquivo de log

# Caminhos
$ftpLogPath = "C:\inetpub\logs\LogFiles\FTPSVC2\"
$scriptLog  = "C:\fail2banWin\fail2banwin_log.txt"

# Configurações
$threshold = 5          # número de falhas antes do bloqueio
$blockTime = 60         # tempo de bloqueio em minutos
$whitelist = @("127.0.0.1","192.168.15.3")

Write-Host "Monitorando FTP e SMB... Pressione CTRL+C para parar."

# Função para registrar no log
function Write-Log {
    param([string]$message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $scriptLog -Value "$timestamp - $message"
}

# Função para aplicar bloqueio
function Block-IP {
    param([string]$ip,[string]$service)
    $ruleName = "Block_${service}_$ip"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        Write-Host "Bloqueando IP $ip ($service) por $blockTime minutos..."
        Write-Log "Bloqueio aplicado ao IP $ip ($service) por $blockTime minutos"
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $ip -Action Block
        # Agenda remoção da regra
        Start-Job -ScriptBlock {
            param($ruleName, $blockTime, $scriptLog)
            Start-Sleep -Seconds ($blockTime * 60)
            Remove-NetFirewallRule -DisplayName $ruleName
            $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Add-Content -Path $scriptLog -Value "$timestamp - Bloqueio removido do IP $ruleName"
        } -ArgumentList $ruleName, $blockTime, $scriptLog | Out-Null
    }
}

# Loop infinito
while ($true) {
    ### --- FTP ---
    $latestLog = Get-ChildItem $ftpLogPath -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $ftpCounts = @{}
    if ($latestLog) {
        $failedLines = Select-String -Path $latestLog.FullName -Pattern "530" -ErrorAction SilentlyContinue
        if ($failedLines) {
            foreach ($line in $failedLines) {
                $parts = $line.Line.Split(" ")
                if ($parts.Length -ge 3) {
                    $ip = $parts[2]
                    if ($ip -and -not $whitelist.Contains($ip)) {
                        if ($ftpCounts.ContainsKey($ip)) { $ftpCounts[$ip]++ } else { $ftpCounts[$ip] = 1 }
                    }
                }
            }
            foreach ($ip in $ftpCounts.Keys) {
                Write-Host "FTP: IP $ip teve $($ftpCounts[$ip]) falhas"
                if ($ftpCounts[$ip] -ge $threshold) { Block-IP $ip "FTP" }
            }
        } else {
            Write-Host "Nenhuma falha FTP encontrada no log atual."
        }
    } else {
        Write-Host "Nenhum arquivo de log FTP encontrado em $ftpLogPath"
    }

    ### --- SMB ---
    $failedEventsSMB = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -ErrorAction SilentlyContinue
    $smbCounts = @{}
    if ($failedEventsSMB) {
        foreach ($event in $failedEventsSMB) {
            $ip = $event.Properties[19].Value
            if ($ip -and -not $whitelist.Contains($ip)) {
                if ($smbCounts.ContainsKey($ip)) { $smbCounts[$ip]++ } else { $smbCounts[$ip] = 1 }
            }
        }
        if ($smbCounts.Count -gt 0) {
            foreach ($ip in $smbCounts.Keys) {
                Write-Host "SMB: IP $ip teve $($smbCounts[$ip]) falhas"
                if ($smbCounts[$ip] -ge $threshold) { Block-IP $ip "SMB" }
            }
        } else {
            Write-Host "Nenhum IP com falhas SMB encontrado."
        }
    } else {
        Write-Host "Nenhum evento SMB (4625) encontrado."
    }

    # Espera antes de checar novamente
    Start-Sleep -Seconds 30
}

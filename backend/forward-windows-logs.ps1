
# ============================================================
# SentinelX - Windows Security Log Forwarder
# Sends new Windows Security events to the SentinelX backend.
# ============================================================

$ErrorActionPreference = "Stop"

$apiUrl = "http://127.0.0.1:8001/api/logs/ingest"

# ------------------------------------------------------------
# 1. Read and validate the ingest key
# ------------------------------------------------------------

$ingestKey = Read-Host "Enter your saved SentinelX ingest key"

# Remove leading/trailing whitespace and accidental control chars.
$ingestKey = $ingestKey -replace '[\x00-\x1F\x7F]', ''

if ([string]::IsNullOrWhiteSpace($ingestKey)) {
    throw "Ingest key is empty. Restart and enter your saved key."
}

# ------------------------------------------------------------
# 2. Verify that the Windows Security log is accessible
# ------------------------------------------------------------

try {
    $latestEvent = Get-WinEvent -LogName Security -MaxEvents 1
    $lastRecordId = [long]$latestEvent.RecordId
}
catch {
    throw "Cannot read Windows Security log. Run PowerShell as Administrator. Details: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "SentinelX Windows collector started." -ForegroundColor Green
Write-Host "API: $apiUrl"
Write-Host "Monitoring new Security events..."
Write-Host "Initial record ID: $lastRecordId"
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# ------------------------------------------------------------
# 3. Poll for new events and forward them
# ------------------------------------------------------------

while ($true) {
    try {
        $xpath = "*[System[EventRecordID > $lastRecordId]]"

        $events = @(
            Get-WinEvent -LogName Security -FilterXPath $xpath `
                -ErrorAction SilentlyContinue |
            Sort-Object RecordId
        )

        if ($events.Count -gt 0) {
            $batch = @()
            $batchLastRecordId = $lastRecordId

            foreach ($event in $events) {
                if ([long]$event.RecordId -le $lastRecordId) {
                    continue
                }

                # Clean invalid control characters from event messages.
                $message = [string]$event.Message
                $message = $message -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' '

                $batch += @{
                    source      = $env:COMPUTERNAME
                    source_type = "windows"
                    event_type  = "windows_event"
                    event_id    = [string]$event.Id
                    severity    = "info"
                    message     = $message
                    username    = [string]$event.UserId
                    hostname    = [string]$event.MachineName
                    timestamp   = $event.TimeCreated.ToUniversalTime().ToString("o")
                }

                $batchLastRecordId = [long]$event.RecordId
            }

            if ($batch.Count -gt 0) {
                $body = @{ logs = $batch } | ConvertTo-Json -Depth 6 -Compress
                $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

                try {
                    $headers = @{
                        "X-Ingest-Key" = $ingestKey
                    }

                    $response = Invoke-RestMethod `
                        -Uri $apiUrl `
                        -Method POST `
                        -Headers $headers `
                        -ContentType "application/json; charset=utf-8" `
                        -Body $bodyBytes `
                        -ErrorAction Stop

                    Write-Host "Successfully submitted $($batch.Count) event(s)." -ForegroundColor Green
                    $response | ConvertTo-Json -Depth 5

                    # Advance only after a successful response.
                    $lastRecordId = $batchLastRecordId
                }
                catch {
                    Write-Warning "Failed to submit events. Will retry from record $($lastRecordId + 1)."
                    Write-Warning "HTTP/Request error: $($_.Exception.Message)"

                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        Write-Warning "Server response: $($_.ErrorDetails.Message)"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Collector error: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 5
}

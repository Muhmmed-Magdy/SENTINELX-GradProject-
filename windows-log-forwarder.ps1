# AI SOC Dashboard - Windows Log Forwarder
# Collects meaningful security events from Windows Event Logs
# Run via START-SOC-FORWARDER.bat for Security log access

param(
    [string]$ApiUrl = "http://localhost:8001/api/logs/ingest",
    [string]$IngestKey = $env:INGEST_KEY,
    [int]$IntervalSeconds = 5
)

$ErrorActionPreference = "Continue"

if (-not $IngestKey) {
    Write-Host "ERROR: IngestKey is not set." -ForegroundColor Red
    Write-Host "  Set the INGEST_KEY environment variable, or pass -IngestKey <key>" -ForegroundColor Yellow
    Write-Host "  Generate a key: Dashboard → Settings → Ingest Keys → Add Key" -ForegroundColor Yellow
    exit 1
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  AI SOC Dashboard - Log Forwarder        " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "API     : $ApiUrl" -ForegroundColor Yellow
Write-Host "Interval: every $IntervalSeconds seconds" -ForegroundColor Yellow
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "Running as Administrator - Security log ENABLED" -ForegroundColor Green
} else {
    Write-Host "WARNING: Not Administrator - Security log DISABLED" -ForegroundColor Yellow
    Write-Host "Double-click START-SOC-FORWARDER.bat for full access" -ForegroundColor Yellow
}
Write-Host ""

# -- Security event IDs that are actually meaningful (blocks 5379 credential spam etc.) --
$SecurityAllowedIds = @(
    4624,  # Successful logon
    4625,  # Failed logon  <-- brute force detection
    4634,  # Logoff
    4647,  # User-initiated logoff
    4648,  # Logon with explicit credentials
    4670,  # Permissions on object changed
    4672,  # Special privileges assigned (admin logon)
    4688,  # New process created
    4689,  # Process exited
    4698,  # Scheduled task created
    4699,  # Scheduled task deleted
    4719,  # System audit policy changed
    4720,  # User account created
    4722,  # User account enabled
    4723,  # Password change attempt
    4724,  # Password reset attempt
    4725,  # User account disabled
    4726,  # User account deleted
    4728,  # Member added to security group
    4732,  # Member added to local group
    4740,  # User account locked out  <-- brute force result
    4756,  # Member added to universal group
    4767,  # User account unlocked
    4771,  # Kerberos pre-auth failed
    4776,  # NTLM credential validation
    4800,  # Workstation locked
    4801,  # Workstation unlocked
    7045   # New service installed  <-- malware persistence
)

# -- PowerShell event IDs to collect (exclude 4100 scripting warnings — too noisy)
$PSAllowedIds = @(
    4103,  # Pipeline execution details
    4104,  # Script block logging  <-- detects encoded/malicious scripts
    4105,  # Started invocation
    4106   # Completed invocation
    # 4100 intentionally excluded: it fires for every script warning including our own forwarder
)

# -- Noisy Application providers to skip --
$AppSkipProviders = @(
    "Microsoft-Windows-Security-SPP",
    "SecurityCenter",
    "Microsoft-Windows-Winlogon"
)

# -- Start time - look back 3 minutes on first run --
$StartTime = (Get-Date).AddMinutes(-3)
$LastSeen  = @{}

# -- Channels to monitor --
$Channels = @(
    "Application",
    "System",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational"
)
if ($isAdmin) { $Channels += "Security" }

foreach ($ch in $Channels) { $LastSeen[$ch] = $StartTime }

# -- Convert event to API format --
function Convert-Event {
    param($Event, [string]$Channel)

    $severity = switch ($Event.LevelDisplayName) {
        "Critical" { "critical" }
        "Error"    { "high"     }
        "Warning"  { "medium"   }
        default    { "info"     }
    }

    # Elevate for critical security events
    if ($Channel -eq "Security") {
        if (@(4625,4740,4771) -contains $Event.Id) { $severity = "high"     }
        if (@(4720,4719,7045) -contains $Event.Id) { $severity = "critical" }
    }

    # Extract username for Security events
    $username = ""
    if ($Channel -eq "Security" -and $Event.Properties.Count -gt 1) {
        try {
            $u = [string]$Event.Properties[1].Value
            if ($u.Length -gt 0 -and $u.Length -lt 100 -and $u -ne "-") { $username = $u }
        } catch {}
    }

    # Extract source IP for logon events
    $sourceIp = ""
    if (@(4624,4625,4648) -contains $Event.Id -and $Event.Properties.Count -gt 18) {
        try {
            $ip = [string]$Event.Properties[18].Value
            if ($ip -and $ip -ne "::1" -and $ip -ne "-" -and $ip -notmatch "^0\.") { $sourceIp = $ip }
        } catch {}
    }

    # Clean message
    $msg = if ($Event.Message) {
        $cleaned = $Event.Message.Trim() -replace '\s+', ' '
        if ($cleaned.Length -gt 500) { $cleaned.Substring(0, 500) } else { $cleaned }
    } else {
        "Event ID $($Event.Id) from $($Event.ProviderName)"
    }

    return @{
        timestamp   = $Event.TimeCreated.ToUniversalTime().ToString("o")
        source      = $env:COMPUTERNAME
        source_type = "windows"
        event_type  = $Event.ProviderName
        event_id    = [string]$Event.Id
        severity    = $severity
        message     = $msg
        raw_log     = $msg
        username    = $username
        hostname    = $env:COMPUTERNAME
        source_ip   = $sourceIp
        tags        = @("windows", $Channel.Split("/")[0].Split("-")[-1])
    }
}

# -- Send batch to API --
function Send-Batch {
    param([array]$Logs)
    if ($Logs.Count -eq 0) { return 0 }
    $body = @{ logs = $Logs } | ConvertTo-Json -Depth 8 -Compress
    try {
        $headers = @{ "X-Ingest-Key" = $IngestKey; "Content-Type" = "application/json" }
        $resp = Invoke-RestMethod -Uri $ApiUrl -Method Post -Body $body -Headers $headers -TimeoutSec 10
        return $resp.ingested
    } catch {
        Write-Host "  API error: $_" -ForegroundColor Red
        return 0
    }
}

# -- Get new events from a channel --
function Get-NewEvents {
    param([string]$Channel)
    try {
        $filter = @{ LogName = $Channel; StartTime = $LastSeen[$Channel] }
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents 100 -ErrorAction SilentlyContinue
        if (-not $raw) { return @() }

        # Filter Security to allowed IDs only - blocks credential read spam
        if ($Channel -eq "Security") {
            $raw = $raw | Where-Object { $SecurityAllowedIds -contains $_.Id }
        }

        # Filter PowerShell channel - only collect script block and execution events, not warnings
        if ($Channel -eq "Microsoft-Windows-PowerShell/Operational") {
            $raw = $raw | Where-Object { $PSAllowedIds -contains $_.Id }
        }

        # Filter Application to skip noisy providers
        if ($Channel -eq "Application") {
            $raw = $raw | Where-Object { $AppSkipProviders -notcontains $_.ProviderName }
        }

        if (-not $raw) { return @() }
        return @($raw | Where-Object { $_.TimeCreated -gt $LastSeen[$Channel] })
    } catch {
        return @()
    }
}

# -- Main loop --

Write-Host "Monitoring $($Channels.Count) channels:" -ForegroundColor Cyan
$Channels | ForEach-Object { Write-Host "  + $_" -ForegroundColor White }
Write-Host ""
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

$totalStored = 0
$cycle = 0

while ($true) {
    $cycle++
    $allLogs = @()
    $summary = @()

    foreach ($channel in $Channels) {
        $events = Get-NewEvents -Channel $channel
        if ($events.Count -gt 0) {
            $converted = @($events | ForEach-Object { Convert-Event $_ $channel })
            $allLogs  += $converted
            $summary  += "$($channel.Split('/')[-1].Split('-')[-1])($($events.Count))"
            $newest    = ($events | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
            $LastSeen[$channel] = $newest
        }
    }

    if ($allLogs.Count -gt 0) {
        $ts = Get-Date -Format "HH:mm:ss"
        Write-Host "[$ts] $($summary -join ' | ')" -ForegroundColor Cyan
        $stored = Send-Batch -Logs $allLogs
        $totalStored += $stored
        $col = if ($stored -gt 0) { "Green" } else { "DarkGray" }
        Write-Host "  Sent: $($allLogs.Count)  Stored: $stored  Total: $totalStored" -ForegroundColor $col
    } else {
        if ($cycle % 12 -eq 0) {
            Write-Host "  $(Get-Date -Format 'HH:mm:ss')  Quiet - Total stored: $totalStored" -ForegroundColor DarkGray
        }
    }

    Start-Sleep -Seconds $IntervalSeconds
}

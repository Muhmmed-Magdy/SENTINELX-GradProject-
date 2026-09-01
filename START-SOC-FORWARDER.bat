@echo off
title SOC Log Forwarder (Admin)
:: Navigate to the script's directory using %~dp0 (works from any location)
cd /d "%~dp0"

:: ── Self-elevate to Administrator ────────────────────────────────────────────
:: Security log collection requires Administrator privileges.
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ── Launch forwarder — key is loaded inside PowerShell, never in CMD args ────
:: The INGEST_KEY is read from .env by PowerShell directly so it is never
:: visible in the process command-line arguments or Windows process listings.
powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -Command ^
  "& { ^
    $envFile = Join-Path $PSScriptRoot '.env'; ^
    if (Test-Path $envFile) { ^
      Get-Content $envFile | ForEach-Object { ^
        if ($_ -match '^([^#=]+)=(.*)$') { ^
          [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), 'Process') ^
        } ^
      } ^
    }; ^
    if (-not $env:INGEST_KEY) { ^
      Write-Host 'ERROR: INGEST_KEY not found in .env file.' -ForegroundColor Red; ^
      Write-Host 'Add INGEST_KEY=<your-key> to: ' + $envFile -ForegroundColor Yellow; ^
      Write-Host 'Generate a key: Dashboard -> Settings -> Ingest Keys -> Add Key' -ForegroundColor Yellow; ^
      pause; exit 1 ^
    }; ^
    & (Join-Path $PSScriptRoot 'windows-log-forwarder.ps1') ^
  }"

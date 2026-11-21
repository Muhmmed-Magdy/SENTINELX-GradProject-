@echo off
setlocal
title SentinelX Launcher

set "PROJECT=D:\GradProject"
set "BACKEND=%PROJECT%\backend"
set "FRONTEND=%PROJECT%\frontend"
set "PYTHON=%BACKEND%\.venv\Scripts\python.exe"
set "COLLECTOR=%BACKEND%\forward-windows-logs.ps1"

echo ==========================================
echo        SentinelX One-Click Launcher
echo ==========================================
echo.

if not exist "%PYTHON%" (
    echo ERROR: Backend Python was not found:
    echo "%PYTHON%"
    echo.
    pause
    exit /b 1
)

if not exist "%FRONTEND%\package.json" (
    echo ERROR: Frontend package.json was not found:
    echo "%FRONTEND%\package.json"
    echo.
    pause
    exit /b 1
)

if not exist "%COLLECTOR%" (
    echo ERROR: Windows log collector was not found:
    echo "%COLLECTOR%"
    echo.
    pause
    exit /b 1
)

echo Starting backend in a separate terminal...
start "SentinelX Backend - port 8001" cmd.exe /k "cd /d ""%BACKEND%"" && ""%PYTHON%"" run.py"

timeout /t 2 /nobreak >nul

echo Starting frontend in a separate terminal...
start "SentinelX Frontend - port 5173" cmd.exe /k "cd /d ""%FRONTEND%"" && npm.cmd run dev"

echo.
echo Requesting an Administrator PowerShell window for the Windows Security log collector.
echo Windows may show a UAC confirmation. Approve it to allow Security log access.
echo The collector will prompt for your saved ingest key.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoExit -NoProfile -ExecutionPolicy Bypass -File %COLLECTOR%'"

echo.
echo Startup commands have been launched.
echo Keep the backend, frontend, and collector windows open while using SentinelX.
echo Close this launcher window when finished; the other windows remain open.
echo.
pause
endlocal

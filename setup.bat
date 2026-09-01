@echo off
echo AI SOC Dashboard - Quick Start
echo ================================

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is required. Please install Python 3.9+
    pause
    exit /b 1
)

:: Check Node
node --version >nul 2>&1
if errorlevel 1 (
    echo Node.js is required. Please install Node.js 18+
    pause
    exit /b 1
)

echo Installing backend dependencies...
cd backend
pip install -r requirements.txt -q

if not exist .env (
    copy .env.example .env
    echo Created .env file
)

echo Installing frontend dependencies...
cd ..\frontend
call npm install

echo.
echo ================================
echo Setup complete!
echo.
echo To start:
echo   1. Backend:  cd backend ^&^& python run.py
echo   2. Frontend: cd frontend ^&^& npm run dev
echo.
echo Then open: http://localhost:5173
echo ================================
pause

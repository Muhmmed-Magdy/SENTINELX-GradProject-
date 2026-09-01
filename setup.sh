#!/bin/bash
# AI SOC Dashboard - Quick Start Script

echo "🛡️  AI SOC Dashboard - Starting..."
echo "================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required. Please install Python 3.9+"
    exit 1
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required. Please install Node.js 18+"
    exit 1
fi

echo "📦 Installing backend dependencies..."
cd backend
python3 -m pip install -r requirements.txt --quiet

# Create .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file from template"
fi

echo "📦 Installing frontend dependencies..."
cd ../frontend
npm install --silent

echo ""
echo "================================="
echo "✅ Setup complete!"
echo ""
echo "To start the dashboard:"
echo "  1. Start backend:  cd backend && python3 run.py"
echo "  2. Start frontend: cd frontend && npm run dev"
echo ""
echo "Then open: http://localhost:5173"
echo "API health: http://localhost:8001/api/health"
echo "================================="

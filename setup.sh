#!/bin/bash
# ThreatSentinel Lite - One-Command Setup Script
# Detects OS and sets up python virtual environment and node modules.

echo "===================================================="
echo " Starting setup for ThreatSentinel Lite..."
echo "===================================================="

# Check Python installation
if ! command -v python &> /dev/null
then
    echo "[-] Python could not be found. Please install Python 3.10+ and add it to your PATH."
    exit 1
fi

# Check Node installation
if ! command -v node &> /dev/null
then
    echo "[-] Node.js could not be found. Please install Node.js (v18+) and npm."
    exit 1
fi

# 1. Setting up Python Virtual Environment
echo ""
echo "[*] Setting up Python Virtual Environment..."
python -m venv venv

# Detect OS to activate virtual environment
OS_NAME="$(uname -s 2>/dev/null || echo "Windows")"
if [[ "$OS_NAME" == *"MONG"* || "$OS_NAME" == *"Msys"* || "$OS_NAME" == *"Windows"* || "$OS_NAME" == *"NT"* ]]; then
    echo "[*] Windows environment detected."
    # Use python directly if activation script varies, or run relative path
    VENV_PIP="./venv/Scripts/pip"
    VENV_PYTHON="./venv/Scripts/python"
else
    echo "[*] Unix-like environment detected (Linux/macOS)."
    VENV_PIP="./venv/bin/pip"
    VENV_PYTHON="./venv/bin/python"
fi

# Install backend dependencies
echo ""
echo "[*] Installing Python backend dependencies..."
$VENV_PIP install --upgrade pip
$VENV_PIP install -r backend/requirements.txt

# Create models directory if it doesn't exist
mkdir -p ml_engine/models

# 2. Setting up React Frontend
echo ""
echo "[*] Installing React frontend dependencies..."
if [ -d "frontend" ]; then
    cd frontend
    npm install
    cd ..
else
    echo "[-] Frontend directory not found. Please make sure the folder structure exists."
fi

echo ""
echo "===================================================="
echo " Setup Completed successfully!"
echo "===================================================="
echo "To run the backend:"
echo "  1. Activate virtual env: source venv/bin/activate (Unix) or .\\venv\\Scripts\\activate (Windows)"
echo "  2. Start Flask: python backend/app.py"
echo "To run the frontend:"
echo "  1. Go to frontend: cd frontend"
echo "  2. Start Vite: npm run dev"
echo "===================================================="

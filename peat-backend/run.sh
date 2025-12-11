#!/bin/bash
# PEAT Backend Runner

echo "======================================"
echo "PEAT Forensics Engine Startup"
echo "======================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Check if YARA is installed
if ! python -c "import yara" 2>/dev/null; then
    echo ""
    echo "WARNING: YARA library not found!"
    echo "Install with: brew install yara (macOS) or apt-get install yara (Linux)"
    echo ""
fi

# Start Flask server
echo ""
echo "Starting PEAT backend on http://localhost:5000"
echo "======================================"
python app.py

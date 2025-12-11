#!/bin/bash
# PEAT Backend Startup Script

cd "$(dirname "$0")/peat-backend"

echo "🚀 Starting PEAT Backend..."
source venv/bin/activate
python app.py

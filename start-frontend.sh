#!/bin/bash
# PEAT Frontend Startup Script

cd "$(dirname "$0")/peat-app"

echo "🌐 Starting PEAT Frontend..."
npm run dev

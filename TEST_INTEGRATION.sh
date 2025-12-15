#!/bin/bash

echo "======================================"
echo "PEAT INTEGRATION TEST"
echo "======================================"
echo

# 1. Check backend
echo "1. Testing Python Backend..."
BACKEND_STATUS=$(curl -s http://localhost:5000/health 2>&1)
if echo "$BACKEND_STATUS" | grep -q "healthy"; then
    echo "   ✅ Backend is running and healthy"
else
    echo "   ❌ Backend NOT running"
    echo "   Start with: cd peat-backend && source venv/bin/activate && python app.py"
    exit 1
fi
echo

# 2. Check frontend
echo "2. Testing Next.js Frontend..."
if lsof -ti:3000 > /dev/null 2>&1; then
    echo "   ✅ Frontend is running"
else
    echo "   ❌ Frontend NOT running"
    echo "   Start with: cd peat-app && npm run dev"
    exit 1
fi
echo

# 3. Create a test binary with suspicious strings
echo "3. Creating test binary with IoC indicators..."
cat > /tmp/test_malware.c << 'EOF'
#include <stdio.h>
int main() {
    char *ip1 = "192.168.1.100";
    char *ip2 = "10.0.0.50";
    char *url = "http://malicious-c2.com/payload";
    char *cmd = "busybox";
    printf("Test binary\n");
    return 0;
}
EOF

gcc -o /tmp/test_binary.elf /tmp/test_malware.c 2>/dev/null
chmod +x /tmp/test_binary.elf
echo "   ✅ Test binary created"
echo

# 4. Test backend analysis directly
echo "4. Testing Backend Analysis..."
RESULT=$(curl -s -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"filepath\": \"/tmp/test_binary.elf\"}")

if echo "$RESULT" | grep -q "success.*true"; then
    echo "   ✅ Backend analysis WORKS!"
    echo
    echo "   Analysis Results:"
    echo "$RESULT" | python3 -m json.tool | grep -A3 "classification\|iocs\|risk_score" | head -20
else
    echo "   ❌ Backend analysis FAILED"
    echo "   Error: $RESULT"
fi
echo

echo "======================================"
echo "INTEGRATION TEST COMPLETE"
echo "======================================"
echo
echo "Next: Go to http://localhost:3000/analyze and upload a file"

#!/bin/bash

# Build verification script for MailX

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== MailX Build Verification ==="
echo

# Check Go version
echo "1. Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo "   [FAIL] Go is not installed"
    exit 1
fi
GO_VERSION=$(go version)
echo "   [OK] $GO_VERSION"

# Check protoc
echo ""
echo "2. Checking Protocol Buffers compiler..."
if ! command -v protoc &> /dev/null; then
    echo "   [WARN] protoc not found (optional for building, required for modifying .proto files)"
else
    PROTOC_VERSION=$(protoc --version)
    echo "   [OK] $PROTOC_VERSION"
fi

# Build server
echo ""
echo "3. Building server..."
cd "$ROOT/server"
mkdir -p bin
if go build -o bin/mailx-server cmd/server/main.go 2>&1; then
    SIZE=$(ls -lh bin/mailx-server | awk '{print $5}')
    echo "   [OK] Server built successfully ($SIZE)"
else
    echo "   [FAIL] Server build failed"
    exit 1
fi

# Build client
echo ""
echo "4. Building client..."
cd "$ROOT/client"
mkdir -p bin
if go build -o bin/mailx-client cmd/client/main.go 2>&1; then
    SIZE=$(ls -lh bin/mailx-client | awk '{print $5}')
    echo "   [OK] Client built successfully ($SIZE)"
else
    echo "   [FAIL] Client build failed"
    exit 1
fi

# Test server startup
echo ""
echo "5. Testing server startup..."
cd "$ROOT/server"

# Create test config
cat > /tmp/verify-test-config.json <<EOF
{
  "domain": "verify.test",
  "grpcPort": "28443",
  "httpPort": "28080",
  "databasePath": "/tmp/verify-test.db",
  "serverKeyFile": "/tmp/verify-test-key.json",
  "maxMessageSize": 26214400,
  "defaultQuota": 10737418240
}
EOF

timeout 3 ./bin/mailx-server /tmp/verify-test-config.json > /tmp/verify-test.log 2>&1 &
SERVER_PID=$!
sleep 2

if curl -s -f http://localhost:28080/.well-known/mailx-server > /dev/null 2>&1; then
    echo "   [OK] Server started and responding"
else
    echo "   [FAIL] Server not responding"
    cat /tmp/verify-test.log
    exit 1
fi

kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/verify-test* 2>/dev/null || true

echo ""
echo "6. Checking documentation..."
DOCS=(
    "$ROOT/docs/PRD_Server.md"
    "$ROOT/docs/PRD_Client.md"
    "$ROOT/docs/Architecture.md"
    "$ROOT/docs/ThreatModel.md"
    "$ROOT/docs/Protocol.md"
    "$ROOT/docs/Roadmap.md"
)

ALL_DOCS_OK=true
for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        echo "   [OK] $(basename "$doc")"
    else
        echo "   [FAIL] $(basename "$doc") missing"
        ALL_DOCS_OK=false
    fi
done

if [ "$ALL_DOCS_OK" = false ]; then
    exit 1
fi

echo ""
echo "7. Checking demo setup..."
if [ -f "$ROOT/demo/docker-compose.yml" ]; then
    echo "   [OK] Docker Compose configuration"
else
    echo "   [FAIL] Docker Compose configuration missing"
    exit 1
fi

if [ -f "$ROOT/demo/setup.sh" ] && [ -x "$ROOT/demo/setup.sh" ]; then
    echo "   [OK] Demo setup script"
else
    echo "   [FAIL] Demo setup script missing or not executable"
    exit 1
fi

echo ""
echo "=== Build Verification Summary ==="
echo "[OK] Go toolchain working"
echo "[OK] Server builds and starts correctly"
echo "[OK] Client builds successfully"
echo "[OK] All documentation present"
echo "[OK] Demo environment configured"
echo
echo "MailX is ready to use."
echo
echo "Next steps:"
echo "  - Run the demo: cd demo && ./setup.sh"
echo "  - Read the docs: see docs/ directory"
echo "  - Quick start: see QUICKSTART.md"
echo ""

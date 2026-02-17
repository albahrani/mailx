#!/bin/bash

# Build verification script for MailX

set -e

echo "=== MailX Build Verification ==="
echo ""

# Check Go version
echo "1. Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo "   ❌ Go is not installed"
    exit 1
fi
GO_VERSION=$(go version)
echo "   ✅ $GO_VERSION"

# Check protoc
echo ""
echo "2. Checking Protocol Buffers compiler..."
if ! command -v protoc &> /dev/null; then
    echo "   ⚠️  protoc not found (optional for building, required for modifying .proto files)"
else
    PROTOC_VERSION=$(protoc --version)
    echo "   ✅ $PROTOC_VERSION"
fi

# Build server
echo ""
echo "3. Building server..."
cd /home/runner/work/mailx/mailx/server
if go build -o bin/mailx-server cmd/server/main.go 2>&1; then
    SIZE=$(ls -lh bin/mailx-server | awk '{print $5}')
    echo "   ✅ Server built successfully ($SIZE)"
else
    echo "   ❌ Server build failed"
    exit 1
fi

# Build client
echo ""
echo "4. Building client..."
cd /home/runner/work/mailx/mailx/client
if go build -o bin/mailx-client cmd/client/main.go 2>&1; then
    SIZE=$(ls -lh bin/mailx-client | awk '{print $5}')
    echo "   ✅ Client built successfully ($SIZE)"
else
    echo "   ❌ Client build failed"
    exit 1
fi

# Test server startup
echo ""
echo "5. Testing server startup..."
cd /home/runner/work/mailx/mailx/server

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
    echo "   ✅ Server started and responding"
else
    echo "   ❌ Server not responding"
    cat /tmp/verify-test.log
    exit 1
fi

kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/verify-test* 2>/dev/null || true

echo ""
echo "6. Checking documentation..."
DOCS=(
    "/home/runner/work/mailx/mailx/docs/PRD_Server.md"
    "/home/runner/work/mailx/mailx/docs/PRD_Client.md"
    "/home/runner/work/mailx/mailx/docs/Architecture.md"
    "/home/runner/work/mailx/mailx/docs/ThreatModel.md"
    "/home/runner/work/mailx/mailx/docs/Protocol.md"
    "/home/runner/work/mailx/mailx/docs/Roadmap.md"
)

ALL_DOCS_OK=true
for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        echo "   ✅ $(basename $doc)"
    else
        echo "   ❌ $(basename $doc) missing"
        ALL_DOCS_OK=false
    fi
done

if [ "$ALL_DOCS_OK" = false ]; then
    exit 1
fi

echo ""
echo "7. Checking demo setup..."
if [ -f "/home/runner/work/mailx/mailx/demo/docker-compose.yml" ]; then
    echo "   ✅ Docker Compose configuration"
else
    echo "   ❌ Docker Compose configuration missing"
    exit 1
fi

if [ -f "/home/runner/work/mailx/mailx/demo/setup.sh" ] && [ -x "/home/runner/work/mailx/mailx/demo/setup.sh" ]; then
    echo "   ✅ Demo setup script"
else
    echo "   ❌ Demo setup script missing or not executable"
    exit 1
fi

echo ""
echo "=== Build Verification Summary ==="
echo "✅ Go toolchain working"
echo "✅ Server builds and starts correctly"
echo "✅ Client builds successfully"
echo "✅ All documentation present"
echo "✅ Demo environment configured"
echo ""
echo "🎉 MailX is ready to use!"
echo ""
echo "Next steps:"
echo "  - Run the demo: cd demo && ./setup.sh"
echo "  - Read the docs: see docs/ directory"
echo "  - Quick start: see QUICKSTART.md"
echo ""

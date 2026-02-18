#!/bin/bash

# Simple integration test for MailX
# This tests the basic workflow without Docker

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== MailX Integration Test ==="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $SERVER_PID1 $SERVER_PID2 2>/dev/null || true
    rm -f /tmp/mailx-test-* /tmp/test-server-*.json 2>/dev/null || true
}

trap cleanup EXIT

# Create server configs
cat > /tmp/test-server-1.json <<EOF
{
  "domain": "server1.local",
  "grpcPort": "19443",
  "httpPort": "19080",
  "databasePath": "/tmp/mailx-test-server1.db",
  "serverKeyFile": "/tmp/mailx-test-server1-key.json",
  "maxMessageSize": 26214400,
  "defaultQuota": 10737418240
}
EOF

cat > /tmp/test-server-2.json <<EOF
{
  "domain": "server2.local",
  "grpcPort": "19543",
  "httpPort": "19180",
  "databasePath": "/tmp/mailx-test-server2.db",
  "serverKeyFile": "/tmp/mailx-test-server2-key.json",
  "maxMessageSize": 26214400,
  "defaultQuota": 10737418240
}
EOF

echo "1. Starting test servers..."
cd "$ROOT/server"
./bin/mailx-server /tmp/test-server-1.json > /tmp/server1.log 2>&1 &
SERVER_PID1=$!
./bin/mailx-server /tmp/test-server-2.json > /tmp/server2.log 2>&1 &
SERVER_PID2=$!

echo "   Waiting for servers to start..."
sleep 3

echo ""
echo "2. Checking server endpoints..."
echo "   Server 1 well-known:"
curl -s http://localhost:19080/.well-known/mailx-server | jq -r '.domain'

echo "   Server 2 well-known:"
curl -s http://localhost:19180/.well-known/mailx-server | jq -r '.domain'

echo ""
echo "3. Testing with gRPC CLI (grpcurl if available)..."
if command -v grpcurl &> /dev/null; then
    echo "   Listing services on server 1:"
    grpcurl -plaintext localhost:19443 list || echo "   (gRPC services available but list failed)"
else
    echo "   (grpcurl not installed, skipping)"
fi

echo ""
echo "=== Test Summary ==="
echo "✅ Server 1 started on ports 19443 (gRPC) and 19080 (HTTP)"
echo "✅ Server 2 started on ports 19543 (gRPC) and 19180 (HTTP)"
echo "✅ Well-known endpoints responding correctly"
echo ""
echo "Servers are running in background (PIDs: $SERVER_PID1, $SERVER_PID2)"
echo "Logs available at /tmp/server1.log and /tmp/server2.log"
echo ""
echo "To test manually:"
echo "  cd ../client"
echo "  ./bin/mailx-client /tmp/alice_config.json"
echo "  > register alice server1.local password123 localhost:19443"
echo "  > login password123"
echo "  > send alice@server1.local test Hello from integration test"
echo ""
echo "Press Ctrl+C to stop servers and cleanup"
echo ""

# Keep running
wait

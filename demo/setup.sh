#!/bin/bash

# MailX Demo Setup Script

set -e

echo "=== MailX Demo Setup ==="
echo ""

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null && ! command -v docker compose &> /dev/null; then
    echo "Error: docker-compose is not installed"
    exit 1
fi

# Use appropriate docker compose command
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

echo "1. Cleaning up old containers and data..."
$DOCKER_COMPOSE down -v 2>/dev/null || true
rm -rf data/server-* data/client 2>/dev/null || true
mkdir -p data/server-a data/server-b data/server-c data/client

echo ""
echo "1b. Ensuring demo TLS certificate exists..."
if [ ! -f "config/tls.crt" ] || [ ! -f "config/tls.key" ]; then
    if command -v openssl &> /dev/null; then
        echo "Generating self-signed TLS cert (config/tls.crt, config/tls.key)"
        MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
            -keyout config/tls.key -out config/tls.crt \
            -subj "/CN=mailx-demo" \
            -addext "subjectAltName=DNS:server-a.local,DNS:server-b.local,DNS:server-c.local,DNS:alice.local,DNS:bob.local,DNS:carol.local,DNS:localhost,IP:127.0.0.1" \
            >/dev/null 2>&1 || true
    else
        echo "Warning: openssl not found; demo will run without TLS"
    fi
fi

echo ""
echo "2. Building Docker images..."
$DOCKER_COMPOSE build

echo ""
echo "3. Starting servers..."
$DOCKER_COMPOSE up -d server-a server-b server-c

echo ""
echo "4. Waiting for servers to start..."
sleep 5

echo ""
echo "5. Checking server status..."
echo "Server A (alice.local): http://localhost:8080/.well-known/mailx-server"
echo "Server B (bob.local):   http://localhost:8180/.well-known/mailx-server"
echo "Server C (carol.local): http://localhost:8280/.well-known/mailx-server"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Servers are running:"
echo "  - Server A (alice.local): gRPC on localhost:8443"
echo "  - Server B (bob.local):   gRPC on localhost:8543"
echo "  - Server C (carol.local): gRPC on localhost:8643"
echo ""
echo "To run the demo:"
echo "  ./run_demo.sh"
echo ""
echo "To access interactive client:"
echo "  $DOCKER_COMPOSE run --rm client alice_config.json"
echo ""
echo "To stop servers:"
echo "  $DOCKER_COMPOSE down"
echo ""

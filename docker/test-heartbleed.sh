#!/bin/bash

# Heartbleed Test Environment Setup and Testing Script

set -e

echo "🔥 Heartbleed Test Environment 🔥"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Build and start the vulnerable server
print_status "Building Heartbleed vulnerable server..."
docker-compose -f docker-compose.yml build heartbleed-server

print_status "Starting Heartbleed vulnerable server..."
docker-compose -f docker-compose.yml up -d heartbleed-server

# Wait for server to start
print_status "Waiting for server to start (10 seconds)..."
sleep 10

# Check if server is running
if docker-compose -f docker-compose.yml ps heartbleed-server | grep -q "Up"; then
    print_success "Heartbleed vulnerable server is running on localhost:8443"
else
    print_error "Failed to start Heartbleed vulnerable server"
    docker-compose -f docker-compose.yml logs heartbleed-server
    exit 1
fi

echo ""
print_warning "⚠️  SECURITY WARNING ⚠️"
print_warning "This server is intentionally vulnerable to CVE-2014-0160 (Heartbleed)"
print_warning "Only use for testing purposes on isolated networks!"
print_warning "Do NOT expose this to the internet!"
echo ""

# Test if tlsferret binary exists
TLSFERRET_PATH="../target/debug/tlsferret"
if [ ! -f "$TLSFERRET_PATH" ]; then
    TLSFERRET_PATH="../target/release/tlsferret"
fi

if [ ! -f "$TLSFERRET_PATH" ]; then
    print_error "tlsferret binary not found. Please build it first with 'cargo build'"
    exit 1
fi

# Run tlsferret against the vulnerable server
print_status "Testing with tlsferret..."
echo ""
echo "Command: $TLSFERRET_PATH localhost:8443 --timeout 10"
echo "========================================================"

$TLSFERRET_PATH localhost:8443 --timeout 10

echo ""
echo "========================================================"
print_status "Test completed!"

echo ""
print_status "Additional manual testing commands:"
echo "  # Test with OpenSSL s_client:"
echo "    openssl s_client -connect localhost:8443 -tlsextdebug"
echo ""
echo "  # Test with nmap Heartbleed script:"
echo "    nmap -p 8443 --script ssl-heartbleed localhost"
echo ""
echo "  # Stop the test environment:"
echo "    docker-compose -f docker-compose.yml down"

echo ""
print_success "Heartbleed test environment is ready!"
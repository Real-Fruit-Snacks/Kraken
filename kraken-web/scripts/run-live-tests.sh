#!/usr/bin/env bash
#
# Run live E2E tests with Kraken server
#
# Usage:
#   ./scripts/run-live-tests.sh           # Run all live tests
#   ./scripts/run-live-tests.sh --headed  # Run with visible browser
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KRAKEN_ROOT="$(dirname "$PROJECT_ROOT")"

HTTP_PORT=${KRAKEN_HTTP_PORT:-8080}
GRPC_PORT=${KRAKEN_GRPC_PORT:-50051}
WEB_PORT=${KRAKEN_WEB_PORT:-3003}

SERVER_PID=""
cleanup() {
  echo "Cleaning up..."
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Build server if needed
echo "Building Kraken server..."
cd "$KRAKEN_ROOT"
cargo build -p server --quiet 2>/dev/null || cargo build -p server

# Find server binary
SERVER_BIN=""
for path in target/debug/kraken-server target/release/kraken-server; do
  if [ -f "$path" ]; then
    SERVER_BIN="$path"
    break
  fi
done

if [ -z "$SERVER_BIN" ]; then
  echo "Error: kraken-server binary not found"
  exit 1
fi

# Start server
echo "Starting Kraken server (HTTP: $HTTP_PORT, gRPC: $GRPC_PORT)..."
"$SERVER_BIN" \
  --http-port "$HTTP_PORT" \
  --grpc-port "$GRPC_PORT" \
  --db-path ":memory:" \
  --insecure \
  > /tmp/kraken-server.log 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
echo "Waiting for server to be ready..."
for i in {1..30}; do
  if nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null; then
    echo "Server is ready!"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "Error: Server failed to start"
    cat /tmp/kraken-server.log
    exit 1
  fi
  sleep 1
done

# Run Playwright tests
echo "Running live E2E tests..."
cd "$PROJECT_ROOT"

# Pass through any arguments (e.g., --headed)
KRAKEN_WEB_URL="http://localhost:$WEB_PORT" \
KRAKEN_GRPC_URL="http://localhost:$GRPC_PORT" \
npx playwright test --config=playwright.live.config.ts "$@"

echo "Live E2E tests complete!"

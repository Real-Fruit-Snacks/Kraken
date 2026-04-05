#!/usr/bin/env bash
#
# Full E2E test: Kraken server + implant + web UI + Playwright tests
#
# This script runs the complete stack for end-to-end testing:
# 1. Starts Kraken server
# 2. Starts an implant simulator
# 3. Runs Playwright tests against the web UI with real session data
#
# Usage:
#   ./scripts/run-full-e2e.sh           # Run all tests
#   ./scripts/run-full-e2e.sh --headed  # Run with visible browser
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KRAKEN_ROOT="$(dirname "$PROJECT_ROOT")"

HTTP_PORT=${KRAKEN_HTTP_PORT:-8080}
GRPC_PORT=${KRAKEN_GRPC_PORT:-50051}
WEB_PORT=${KRAKEN_WEB_PORT:-3003}

SERVER_PID=""
IMPLANT_PID=""

cleanup() {
  echo "Cleaning up..."
  [ -n "$IMPLANT_PID" ] && kill "$IMPLANT_PID" 2>/dev/null || true
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

cd "$KRAKEN_ROOT"

# Build binaries
echo "Building Kraken server and implant-sim..."
cargo build -p server -p implant-sim --quiet 2>/dev/null || cargo build -p server -p implant-sim

# Find binaries
SERVER_BIN=""
IMPLANT_BIN=""
for path in target/debug/kraken-server target/release/kraken-server; do
  [ -f "$path" ] && SERVER_BIN="$path" && break
done
for path in target/debug/implant-sim target/release/implant-sim; do
  [ -f "$path" ] && IMPLANT_BIN="$path" && break
done

[ -z "$SERVER_BIN" ] && echo "Error: kraken-server not found" && exit 1
[ -z "$IMPLANT_BIN" ] && echo "Error: implant-sim not found" && exit 1

# Start server
echo "Starting Kraken server (HTTP: $HTTP_PORT, gRPC: $GRPC_PORT)..."
"$SERVER_BIN" \
  --http-port "$HTTP_PORT" \
  --grpc-port "$GRPC_PORT" \
  --db-path ":memory:" \
  --insecure \
  > /tmp/kraken-server.log 2>&1 &
SERVER_PID=$!

# Wait for server
echo "Waiting for server..."
for i in {1..30}; do
  nc -z 127.0.0.1 "$HTTP_PORT" 2>/dev/null && break
  [ $i -eq 30 ] && echo "Server failed to start" && cat /tmp/kraken-server.log && exit 1
  sleep 1
done
echo "Server is ready!"

# Start implant (continuous mode with 2-second check-in)
echo "Starting implant simulator..."
"$IMPLANT_BIN" \
  --server "http://127.0.0.1:$HTTP_PORT" \
  --interval 2 \
  > /tmp/implant-sim.log 2>&1 &
IMPLANT_PID=$!

# Wait for implant to register
echo "Waiting for implant registration..."
sleep 3

# Run Playwright tests
echo "Running full E2E tests..."
cd "$PROJECT_ROOT"

KRAKEN_WEB_URL="http://localhost:$WEB_PORT" \
KRAKEN_GRPC_URL="http://localhost:$GRPC_PORT" \
npx playwright test --config=playwright.live.config.ts "$@"

echo "Full E2E tests complete!"

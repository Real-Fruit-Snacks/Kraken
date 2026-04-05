#!/bin/bash
# Loot Store stress test script for Kraken C2
#
# Usage:
#   ./scripts/test-loot-stress.sh [--no-start-server] [--no-cleanup] [--addr <host:port>]
#
# Options:
#   --no-start-server   Skip starting a server; use an already-running one
#   --no-cleanup        Leave test data in the database after the run
#   --addr HOST:PORT    gRPC server address (default: 127.0.0.1:50051)
#   --credentials N     Number of credential entries to insert (default: 1000)
#   --hashes N          Number of hash entries to insert (default: 500)
#   --tokens N          Number of token entries to insert (default: 500)
#   --delete-count N    Number of random entries to delete (default: 100)
#   --page-size N       Pagination page size (default: 100)

set -euo pipefail

KRAKEN_ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
cd "$KRAKEN_ROOT"

# ── Defaults ──────────────────────────────────────────────────────────────────
START_SERVER=true
ADDR="127.0.0.1:50051"
CREDENTIALS=1000
HASHES=500
TOKENS=500
DELETE_COUNT=100
PAGE_SIZE=100
NO_CLEANUP=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-start-server) START_SERVER=false ;;
        --no-cleanup)      NO_CLEANUP=true ;;
        --addr)            ADDR="$2"; shift ;;
        --credentials)     CREDENTIALS="$2"; shift ;;
        --hashes)          HASHES="$2"; shift ;;
        --tokens)          TOKENS="$2"; shift ;;
        --delete-count)    DELETE_COUNT="$2"; shift ;;
        --page-size)       PAGE_SIZE="$2"; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

GRPC_ADDR="http://${ADDR}"
SERVER_PID=""

# ── Cleanup trap ──────────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        echo ""
        echo "[cleanup] Stopping test server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        rm -f /tmp/kraken-stress-test.db
    fi
}
trap cleanup EXIT

# ── Banner ────────────────────────────────────────────────────────────────────
echo "=== Kraken Loot Store Stress Test ==="
echo "  gRPC addr:   $GRPC_ADDR"
echo "  Credentials: $CREDENTIALS"
echo "  Hashes:      $HASHES"
echo "  Tokens:      $TOKENS"
echo "  Deletes:     $DELETE_COUNT"
echo "  Page size:   $PAGE_SIZE"
echo "  Cleanup:     $( [[ "$NO_CLEANUP" == true ]] && echo no || echo yes )"
echo ""

# ── Step 1: Build ─────────────────────────────────────────────────────────────
echo "[1/4] Building server and stress binary..."
T_BUILD_START=$(date +%s%3N)

cargo build --release -p server -p loot-stress 2>&1 | tail -5

T_BUILD_END=$(date +%s%3N)
BUILD_MS=$(( T_BUILD_END - T_BUILD_START ))
echo "      Build complete in ${BUILD_MS}ms"

# ── Step 2: Start server (optional) ──────────────────────────────────────────
if [[ "$START_SERVER" == true ]]; then
    echo ""
    echo "[2/4] Starting kraken-server on ${ADDR}..."
    rm -f /tmp/kraken-stress-test.db

    RUST_LOG=warn ./target/release/kraken-server \
        --grpc-port "${ADDR##*:}" \
        --http-port 18080 \
        --db-path /tmp/kraken-stress-test.db \
        &>/tmp/kraken-stress-server.log &
    SERVER_PID=$!

    # Wait up to 10s for the gRPC port to open
    MAX_WAIT=10
    for i in $(seq 1 $MAX_WAIT); do
        if nc -z "${ADDR%%:*}" "${ADDR##*:}" 2>/dev/null; then
            echo "      Server ready (PID $SERVER_PID, waited ${i}s)"
            break
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "ERROR: Server exited unexpectedly. Logs:" >&2
            cat /tmp/kraken-stress-server.log >&2
            exit 1
        fi
        if [[ "$i" -eq "$MAX_WAIT" ]]; then
            echo "ERROR: Server did not open port ${ADDR} within ${MAX_WAIT}s" >&2
            cat /tmp/kraken-stress-server.log >&2
            exit 1
        fi
        sleep 1
    done
else
    echo ""
    echo "[2/4] Skipping server start (--no-start-server); using $GRPC_ADDR"
fi

# ── Step 3: Run Rust stress binary ────────────────────────────────────────────
echo ""
echo "[3/4] Running loot-stress binary..."

CLEANUP_FLAG=""
if [[ "$NO_CLEANUP" == true ]]; then
    CLEANUP_FLAG="--no-cleanup"
fi

T_STRESS_START=$(date +%s%3N)
./target/release/loot-stress \
    --addr "$GRPC_ADDR" \
    --credentials "$CREDENTIALS" \
    --hashes "$HASHES" \
    --tokens "$TOKENS" \
    --delete-count "$DELETE_COUNT" \
    --page-size "$PAGE_SIZE" \
    $CLEANUP_FLAG
STRESS_EXIT=$?
T_STRESS_END=$(date +%s%3N)
STRESS_MS=$(( T_STRESS_END - T_STRESS_START ))

# ── Step 4: Summary ───────────────────────────────────────────────────────────
echo ""
echo "[4/4] Wall-clock times:"
echo "      Build:       ${BUILD_MS}ms"
echo "      Stress run:  ${STRESS_MS}ms"
echo ""

if [[ $STRESS_EXIT -eq 0 ]]; then
    echo "=== STRESS TEST PASSED ==="
    exit 0
else
    echo "=== STRESS TEST FAILED (exit $STRESS_EXIT) ===" >&2
    exit $STRESS_EXIT
fi

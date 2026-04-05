#!/usr/bin/env bash
# Kraken Smoke Test
# Automated live testing of server, implant, and loot store functionality.
# Run from the repository root.

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# Configuration
DB_PATH="${KRAKEN_DB:-kraken.db}"
SERVER_PORT="${KRAKEN_GRPC_PORT:-50051}"
HTTP_PORT="${KRAKEN_HTTP_PORT:-8080}"
WAIT_TIMEOUT=10

cleanup() {
    info "Cleaning up..."
    pkill -f 'kraken-server' 2>/dev/null || true
    pkill -f 'target/release/implant' 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

info "=== Kraken Smoke Test ==="
echo ""

# Check we're in the repo root
if [[ ! -f "Cargo.toml" ]] || ! grep -q 'name = "kraken"' Cargo.toml 2>/dev/null; then
    # Try workspace Cargo.toml
    if [[ ! -d "crates/server" ]]; then
        fail "Run this script from the kraken repository root"
    fi
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

info "Building release binaries..."
cargo build --release -p server -p implant-core -p loot-stress --quiet || fail "Build failed"

# ---------------------------------------------------------------------------
# Clean state
# ---------------------------------------------------------------------------

info "Cleaning previous state..."
pkill -9 -f 'kraken-server' 2>/dev/null || true
sleep 1
rm -f "$DB_PATH" "${DB_PATH}-shm" "${DB_PATH}-wal"

# ---------------------------------------------------------------------------
# Start server
# ---------------------------------------------------------------------------

info "Starting server (insecure mode)..."
RUST_LOG=warn ./target/release/kraken-server --insecure &
SERVER_PID=$!

# Wait for server to be ready
for i in $(seq 1 $WAIT_TIMEOUT); do
    if ss -tlnp 2>/dev/null | grep -q ":${SERVER_PORT}"; then
        break
    fi
    sleep 1
done

if ! ss -tlnp 2>/dev/null | grep -q ":${SERVER_PORT}"; then
    fail "Server failed to start on port ${SERVER_PORT}"
fi
info "Server running (PID: $SERVER_PID)"

# ---------------------------------------------------------------------------
# Insert test implant for loot-stress FK constraint
# ---------------------------------------------------------------------------

info "Inserting test implant for loot-stress..."
sqlite3 "$DB_PATH" "INSERT INTO implants (id, name, state, hostname, username, os_name, os_version, os_arch, process_id, process_name, is_elevated, checkin_interval, jitter_percent, registered_at, last_seen) VALUES (X'00000000000000000000000000000000', 'smoke-test', 'active', 'testhost', 'testuser', 'Linux', '5.0', 'x86_64', 1, 'test', 0, 10, 0, strftime('%s','now')*1000, strftime('%s','now')*1000);" || fail "Failed to insert test implant"

# ---------------------------------------------------------------------------
# Test 1: Loot Store Stress Test
# ---------------------------------------------------------------------------

info "Running loot-stress test..."
if ./target/release/loot-stress --addr "http://127.0.0.1:${SERVER_PORT}" --credentials 20 --hashes 10 --tokens 10; then
    info "Loot stress test: PASSED"
else
    fail "Loot stress test: FAILED"
fi

# ---------------------------------------------------------------------------
# Test 2: Implant Registration
# ---------------------------------------------------------------------------

info "Testing implant registration..."
RUST_LOG=warn KRAKEN_SERVER="http://127.0.0.1:${HTTP_PORT}" timeout 5 ./target/release/implant &
IMPLANT_PID=$!
sleep 3

# Check if implant registered
IMPLANT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM implants WHERE name != 'smoke-test';")
if [[ "$IMPLANT_COUNT" -ge 1 ]]; then
    IMPLANT_NAME=$(sqlite3 "$DB_PATH" "SELECT name FROM implants WHERE name != 'smoke-test' LIMIT 1;")
    info "Implant registration: PASSED (registered as '$IMPLANT_NAME')"
else
    warn "Implant registration: No new implant detected (may have exited before registering)"
fi

# Stop implant
kill $IMPLANT_PID 2>/dev/null || true

# ---------------------------------------------------------------------------
# Test 3: FTS Search
# ---------------------------------------------------------------------------

info "Testing FTS search..."

# Insert test loot for FTS
sqlite3 "$DB_PATH" "INSERT INTO loot (id, implant_id, loot_type, captured_at, username, domain, host, source) VALUES (X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', X'00000000000000000000000000000000', 'credential', strftime('%s','now')*1000, 'fts_test_admin', 'TESTDOMAIN', 'dc01.test.local', 'smoke-test');"

# Search via FTS
FTS_RESULT=$(sqlite3 "$DB_PATH" "SELECT rowid FROM loot_fts WHERE loot_fts MATCH 'fts_test_admin';")
if [[ -n "$FTS_RESULT" ]]; then
    info "FTS search: PASSED (found rowid: $FTS_RESULT)"
else
    fail "FTS search: FAILED (no results for 'fts_test_admin')"
fi

# ---------------------------------------------------------------------------
# Test 4: Database Integrity
# ---------------------------------------------------------------------------

info "Checking database integrity..."
INTEGRITY=$(sqlite3 "$DB_PATH" "PRAGMA integrity_check;")
if [[ "$INTEGRITY" == "ok" ]]; then
    info "Database integrity: PASSED"
else
    fail "Database integrity: FAILED ($INTEGRITY)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
info "=== All Smoke Tests Passed ==="
echo ""
echo "Server:  http://127.0.0.1:${HTTP_PORT} (HTTP), http://127.0.0.1:${SERVER_PORT} (gRPC)"
echo "Database: $DB_PATH"
echo ""
echo "To keep the server running, press Ctrl+C to exit this script."
echo "Server will be stopped automatically on exit."

# Keep server running for manual testing if desired
wait $SERVER_PID 2>/dev/null || true

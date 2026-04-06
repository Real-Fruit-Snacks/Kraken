#!/usr/bin/env bash
# Kraken C2 — CLI Smoke Test
# Verifies all 30 task types dispatch successfully against the implant-sim.
# Run from the repository root.

set -uo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERR ]${NC} $*"; }

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_PORT="${KRAKEN_GRPC_PORT:-50051}"
HTTP_PORT="${KRAKEN_HTTP_PORT:-8080}"
SERVER_ADDR="http://127.0.0.1:${SERVER_PORT}"
OPERATOR="./target/debug/kraken-operator"
WAIT_TIMEOUT=15

PASS=0
FAIL=0
TOTAL=0
RESULTS=""

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    info "Cleaning up..."
    pkill -f 'kraken-server' 2>/dev/null || true
    pkill -f 'implant-sim'   2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

info "=== Kraken CLI Smoke Test ==="
echo ""

if [[ ! -f "Cargo.toml" ]] && [[ ! -d "crates/server" ]]; then
    error "Run this script from the kraken repository root"
    exit 1
fi

if [[ ! -x "$OPERATOR" ]]; then
    warn "Operator binary not found at $OPERATOR — building debug binaries..."
    cargo build -p operator -p server -p implant-sim --quiet \
        || { error "Build failed"; exit 1; }
fi

# ---------------------------------------------------------------------------
# Start server
# ---------------------------------------------------------------------------

info "Starting server (insecure mode)..."
pkill -f 'kraken-server' 2>/dev/null || true
sleep 1

RUST_LOG=warn ./target/debug/kraken-server --insecure &
SERVER_PID=$!

# Wait for gRPC port to open
for i in $(seq 1 $WAIT_TIMEOUT); do
    if ss -tlnp 2>/dev/null | grep -q ":${SERVER_PORT}"; then
        break
    fi
    sleep 1
done

if ! ss -tlnp 2>/dev/null | grep -q ":${SERVER_PORT}"; then
    error "Server failed to start on port ${SERVER_PORT}"
    exit 1
fi
info "Server running (PID: $SERVER_PID)"

# ---------------------------------------------------------------------------
# Register simulated implant
# ---------------------------------------------------------------------------

info "Starting implant-sim to register a test implant..."
RUST_LOG=warn KRAKEN_SERVER="http://127.0.0.1:${HTTP_PORT}" \
    ./target/debug/implant-sim &
SIM_PID=$!
sleep 3

# Grab the first registered implant ID
IMPLANT_ID=$(sqlite3 "${KRAKEN_DB:-kraken.db}" \
    "SELECT hex(id) FROM implants LIMIT 1;" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)

if [[ -z "$IMPLANT_ID" ]]; then
    error "No implant registered — cannot dispatch tasks"
    exit 1
fi
info "Implant registered: $IMPLANT_ID"

# ---------------------------------------------------------------------------
# Helper: dispatch one command and record pass/fail
# ---------------------------------------------------------------------------
# Usage: test_command <display-name> <operator-args...>
#
# The operator is expected to:
#   - Exit 0 on successful task dispatch (task ID printed to stdout)
#   - Exit non-zero on parse / dispatch failure
# ---------------------------------------------------------------------------

test_command() {
    local name="$1"
    shift
    local args=("$@")
    TOTAL=$((TOTAL + 1))

    printf "  %-40s " "$name ..."

    local output
    output=$(printf '%s\n' "${args[@]}" \
        | timeout 5 "$OPERATOR" \
            --server "$SERVER_ADDR" \
            --implant "$IMPLANT_ID" \
            --insecure \
            2>/dev/null) && local exit_code=0 || local exit_code=$?

    # Accept dispatch if we got a non-empty response (task ID) and exit 0
    if [[ $exit_code -eq 0 ]] && [[ -n "$output" ]]; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
        RESULTS="${RESULTS}\n  ${GREEN}PASS${NC}  $name"
    else
        echo -e "${RED}FAIL${NC}  (exit=$exit_code)"
        FAIL=$((FAIL + 1))
        RESULTS="${RESULTS}\n  ${RED}FAIL${NC}  $name"
    fi
}

# ---------------------------------------------------------------------------
# Phase 1 — Core
# ---------------------------------------------------------------------------

echo ""
info "Phase 1 — Core"
test_command "shell whoami"   shell "whoami"
test_command "sleep 60"       sleep 60

# ---------------------------------------------------------------------------
# Phase 2 — Filesystem
# ---------------------------------------------------------------------------

info "Phase 2 — Filesystem"
test_command "cd /tmp"                              cd /tmp
test_command "pwd"                                  pwd
test_command "ls /tmp"                              ls /tmp
test_command "upload /tmp/test.txt /tmp/remote.txt" upload /tmp/test.txt /tmp/remote.txt
test_command "download /tmp/remote.txt /tmp/local.txt" download /tmp/remote.txt /tmp/local.txt

# ---------------------------------------------------------------------------
# Phase 3 — Modules
# ---------------------------------------------------------------------------

info "Phase 3 — Modules"
test_command "modules list"   modules list

# ---------------------------------------------------------------------------
# Phase 5 — Mesh
# ---------------------------------------------------------------------------

info "Phase 5 — Mesh"
test_command "mesh topology"  mesh topology

# ---------------------------------------------------------------------------
# Phase 7 — Injection & Tokens
# ---------------------------------------------------------------------------

info "Phase 7 — Injection & Tokens"
test_command "inject shellcode 1234 /tmp/test.bin auto" inject shellcode 1234 /tmp/test.bin auto
test_command "token list"                               token list

# ---------------------------------------------------------------------------
# B1 — Surveillance
# ---------------------------------------------------------------------------

info "B1 — Surveillance"
test_command "keylog start"    keylog start
test_command "keylog stop"     keylog stop
test_command "keylog dump"     keylog dump
test_command "clipboard get"   clipboard get
test_command "clipboard dump"  clipboard dump
test_command "env sysinfo"     env sysinfo
test_command "env whoami"      env whoami
test_command "browser all"     browser all
test_command "audio 5"         audio 5
test_command "webcam"          webcam
test_command "usb list"        usb list
test_command "rdp hijack 1"    rdp hijack 1

# ---------------------------------------------------------------------------
# B2 — Recon & Persistence
# ---------------------------------------------------------------------------

info "B2 — Recon & Persistence"
test_command "reg enum-keys HKLM\\SOFTWARE"              reg enum-keys "HKLM\\SOFTWARE"
test_command "svc list"                                  svc list
test_command "persist list"                              persist list
test_command "scan ports 192.168.1.1 80,443"             scan ports 192.168.1.1 80,443
test_command "ntlm-relay 0.0.0.0 445 10.0.0.1 445"      ntlm-relay 0.0.0.0 445 10.0.0.1 445

# ---------------------------------------------------------------------------
# B3 — Lateral Movement & Credentials
# ---------------------------------------------------------------------------

info "B3 — Lateral Movement & Credentials"
test_command "lateral winrm 10.0.0.1 whoami"  lateral winrm 10.0.0.1 whoami
test_command "ad users"                        ad users
test_command "creds sam"                       creds sam

# ---------------------------------------------------------------------------
# B4 — Visual & Wireless
# ---------------------------------------------------------------------------

info "B4 — Visual & Wireless"
test_command "screenshot"              screenshot
test_command "screenshot-stream 1000"  screenshot-stream 1000
test_command "wifi"                    wifi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "============================================"
echo " CLI Smoke Test Results"
echo "============================================"
echo -e "$RESULTS"
echo ""
echo "  Pass: $PASS / $TOTAL"
echo "  Fail: $FAIL / $TOTAL"
echo "============================================"
echo ""

if [[ $FAIL -gt 0 ]]; then
    warn "$FAIL task type(s) failed dispatch"
fi

exit $FAIL

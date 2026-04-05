#!/bin/bash
# test-mtls.sh — mTLS / TLS connection test suite for Kraken C2
#
# Usage:
#   ./scripts/test-mtls.sh [--certs-dir <dir>] [--grpc-port <port>] [--keep-certs]
#
# Options:
#   --certs-dir   Directory for certificates (default: auto-generated temp dir)
#   --grpc-port   gRPC port to use for the test server (default: 50099)
#   --keep-certs  Do not delete generated certificates on exit
#
# Requirements: openssl, bash >= 4
# The server binary must already be built:  cargo build --release -p server
#
# ── What this script tests ────────────────────────────────────────────────────
#
# ALL TESTS ARE ACTIVE (pass/fail reflects real server behaviour):
#   1. TLS is active — plaintext connections to the gRPC port are rejected
#   2. Server certificate can be verified against the CA
#   3. Server certificate cannot be verified with the wrong CA (client check)
#   4. Server certificate cannot be verified without any CA (client check)
#   5. Expired server certificate is rejected by a correct client
#   6. TLS 1.3 is negotiated (no downgrade to obsolete protocols)
#   7. gRPC request without client cert is rejected UNAUTHENTICATED (grpc-status 16)
#   8. gRPC request with client cert from wrong CA is rejected
#   9. gRPC request with valid client cert reaches the service layer (not status 16)
#
# Client-cert enforcement is implemented via a tonic gRPC interceptor
# (require_client_cert in crates/server/src/auth.rs) that reads the peer
# certificate from TlsConnectInfo request extensions and returns UNAUTHENTICATED
# for requests arriving without a valid client certificate.
#
# Exit codes:
#   0  All active tests passed
#   1  One or more active tests failed

set -uo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
GRPC_PORT=50099
CERTS_DIR=""
KEEP_CERTS=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --certs-dir)  CERTS_DIR="$2";  shift 2 ;;
        --grpc-port)  GRPC_PORT="$2";  shift 2 ;;
        --keep-certs) KEEP_CERTS=true; shift   ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

CERTS_TEMP=false
if [[ -z "$CERTS_DIR" ]]; then
    CERTS_DIR="/tmp/kraken-mtls-test-$$"
    CERTS_TEMP=true
fi

KRAKEN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Counters ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
SERVER_PID=""

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()  { echo -e "  ${YELLOW}$*${RESET}"; }

pass() {
    echo -e "  ${GREEN}PASS${RESET}  $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}FAIL${RESET}  $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "  ${CYAN}SKIP${RESET}  $1"
    SKIP=$((SKIP + 1))
}

# ── TLS probe helpers ─────────────────────────────────────────────────────────

# tls_verify_server CA CERT KEY
#   Connect with the given CA (and optionally a client cert/key).
#   Returns 0 if the server certificate is successfully verified, 1 otherwise.
tls_verify_server() {
    local ca_file="$1"
    local client_cert="${2:-}"
    local client_key="${3:-}"

    local args=(-connect "127.0.0.1:${GRPC_PORT}" -CAfile "$ca_file" -verify_return_error)
    [[ -n "$client_cert" ]] && args+=(-cert "$client_cert" -key "$client_key")

    echo QUIT | openssl s_client "${args[@]}" 2>&1 \
        | grep -q "Verify return code: 0 (ok)"
}

# tls_check_plaintext
#   Returns 0 if a plaintext TCP connection gets a TLS alert back (i.e. server
#   speaks TLS), non-zero if the server accepts raw bytes.
tls_check_plaintext() {
    # Send a bare HTTP/1.1 GET — a TLS server will respond with an alert or
    # close the connection immediately; a plaintext server would reply with HTTP.
    local response
    response=$(printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' \
        | timeout 3 openssl s_client \
            -connect "127.0.0.1:${GRPC_PORT}" \
            -no_tls1_3 -no_tls1_2 -no_tls1_1 -no_tls1 \
            2>&1 || true)
    # If the server speaks TLS, openssl will either negotiate or send an alert;
    # either way a plaintext probe will not see a successful HTTP response.
    # We expect the connection to fail / return an SSL error.
    echo "$response" | grep -qiE "ssl|alert|error|handshake" && return 0
    return 1
}

# tls_get_protocol
#   Prints the negotiated TLS protocol version (e.g. "TLSv1.3").
tls_get_protocol() {
    echo QUIT | openssl s_client \
        -connect "127.0.0.1:${GRPC_PORT}" \
        -CAfile "$1" \
        2>&1 | grep "^Protocol" | awk '{print $2}'
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "── Cleanup ─────────────────────────────────────────────────────────────────"

    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        info "Stopping test server (PID $SERVER_PID)…"
        kill "$SERVER_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi

    if $CERTS_TEMP && ! $KEEP_CERTS; then
        info "Removing temporary certificate directory: $CERTS_DIR"
        rm -rf "$CERTS_DIR"
    else
        info "Certificates retained at: $CERTS_DIR"
    fi

    rm -f "${KRAKEN_ROOT}/kraken-mtls-test-$$.db"
}
trap cleanup EXIT

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "=== Kraken mTLS / TLS Connection Test Suite ==="
echo "    Server binary : ${KRAKEN_ROOT}/target/release/kraken-server"
echo "    gRPC port     : ${GRPC_PORT}"
echo "    Certs dir     : ${CERTS_DIR}"
echo ""

# ── Step 1: Certificates ──────────────────────────────────────────────────────
echo "── Step 1: Certificates ────────────────────────────────────────────────────"

mkdir -p "$CERTS_DIR"

need_gen=false
for f in ca.crt ca.key server.crt server.key operator.crt operator.key; do
    [[ ! -f "${CERTS_DIR}/${f}" ]] && need_gen=true && break
done

if ! $need_gen; then
    info "Using existing certificates in $CERTS_DIR"
else
    info "Generating certificates in $CERTS_DIR…"

    # ── CA ──
    openssl genrsa -out "${CERTS_DIR}/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 \
        -key  "${CERTS_DIR}/ca.key" \
        -out  "${CERTS_DIR}/ca.crt" \
        -subj "/CN=Kraken CA/O=Kraken" 2>/dev/null

    # ── Server cert — SAN required by rustls/tonic ──
    openssl genrsa -out "${CERTS_DIR}/server.key" 2048 2>/dev/null
    openssl req -new \
        -key  "${CERTS_DIR}/server.key" \
        -out  "${CERTS_DIR}/server.csr" \
        -subj "/CN=kraken-server/O=Kraken" 2>/dev/null
    openssl x509 -req -days 365 \
        -in   "${CERTS_DIR}/server.csr" \
        -CA   "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out  "${CERTS_DIR}/server.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost") 2>/dev/null
    rm -f "${CERTS_DIR}/server.csr"

    # ── Operator (client) cert ──
    openssl genrsa -out "${CERTS_DIR}/operator.key" 2048 2>/dev/null
    openssl req -new \
        -key  "${CERTS_DIR}/operator.key" \
        -out  "${CERTS_DIR}/operator.csr" \
        -subj "/CN=operator/O=Kraken" 2>/dev/null
    openssl x509 -req -days 365 \
        -in   "${CERTS_DIR}/operator.csr" \
        -CA   "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out  "${CERTS_DIR}/operator.crt" 2>/dev/null
    rm -f "${CERTS_DIR}/operator.csr"

    info "Base certificates generated"
fi

# ── Ancillary certs ───────────────────────────────────────────────────────────

# Wrong-CA root
if [[ ! -f "${CERTS_DIR}/wrong-ca.crt" ]]; then
    info "Generating wrong-CA certificate…"
    openssl genrsa -out "${CERTS_DIR}/wrong-ca.key" 2048 2>/dev/null
    openssl req -new -x509 -days 3650 \
        -key  "${CERTS_DIR}/wrong-ca.key" \
        -out  "${CERTS_DIR}/wrong-ca.crt" \
        -subj "/CN=Evil CA/O=NotKraken" 2>/dev/null

    # Rogue operator cert signed by the wrong CA
    openssl genrsa -out "${CERTS_DIR}/rogue-operator.key" 2048 2>/dev/null
    openssl req -new \
        -key  "${CERTS_DIR}/rogue-operator.key" \
        -out  "${CERTS_DIR}/rogue-operator.csr" \
        -subj "/CN=rogue/O=NotKraken" 2>/dev/null
    openssl x509 -req -days 365 \
        -in   "${CERTS_DIR}/rogue-operator.csr" \
        -CA   "${CERTS_DIR}/wrong-ca.crt" \
        -CAkey "${CERTS_DIR}/wrong-ca.key" \
        -CAcreateserial \
        -out  "${CERTS_DIR}/rogue-operator.crt" 2>/dev/null
    rm -f "${CERTS_DIR}/rogue-operator.csr"

    # Wrong-CA server cert (for client-side verification test)
    openssl genrsa -out "${CERTS_DIR}/wrong-server.key" 2048 2>/dev/null
    openssl req -new \
        -key  "${CERTS_DIR}/wrong-server.key" \
        -out  "${CERTS_DIR}/wrong-server.csr" \
        -subj "/CN=kraken-server/O=NotKraken" 2>/dev/null
    openssl x509 -req -days 365 \
        -in   "${CERTS_DIR}/wrong-server.csr" \
        -CA   "${CERTS_DIR}/wrong-ca.crt" \
        -CAkey "${CERTS_DIR}/wrong-ca.key" \
        -CAcreateserial \
        -out  "${CERTS_DIR}/wrong-server.crt" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost") 2>/dev/null
    rm -f "${CERTS_DIR}/wrong-server.csr"
fi

# Expired server cert (for client-side expiry test)
if [[ ! -f "${CERTS_DIR}/expired-server.crt" ]]; then
    info "Generating expired server certificate…"
    openssl genrsa -out "${CERTS_DIR}/expired-server.key" 2048 2>/dev/null
    openssl req -new \
        -key  "${CERTS_DIR}/expired-server.key" \
        -out  "${CERTS_DIR}/expired-server.csr" \
        -subj "/CN=kraken-server/O=Kraken" 2>/dev/null
    # Try OpenSSL ≥ 3.x date flags; fall back to a fixed past window
    openssl x509 -req \
        -in   "${CERTS_DIR}/expired-server.csr" \
        -CA   "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out  "${CERTS_DIR}/expired-server.crt" \
        -not_before "$(date -d '3 days ago' +%y%m%d%H%M%SZ 2>/dev/null || echo '230101000000Z')" \
        -not_after  "$(date -d '2 days ago' +%y%m%d%H%M%SZ 2>/dev/null || echo '230102000000Z')" \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost") 2>/dev/null || \
    openssl x509 -req \
        -in   "${CERTS_DIR}/expired-server.csr" \
        -CA   "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out  "${CERTS_DIR}/expired-server.crt" \
        -startdate 20230101000000Z \
        -enddate   20230102000000Z \
        -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:localhost") 2>/dev/null || true
    rm -f "${CERTS_DIR}/expired-server.csr"
fi

info "All certificates ready"

# ── Step 2: Start server with mTLS ────────────────────────────────────────────
echo ""
echo "── Step 2: Start server ────────────────────────────────────────────────────"

SERVER_BIN="${KRAKEN_ROOT}/target/release/kraken-server"
if [[ ! -x "$SERVER_BIN" ]]; then
    echo "ERROR: server binary not found — run: cargo build --release -p server" >&2
    exit 1
fi

# Abort if chosen port is already in use
if ss -tlnp 2>/dev/null | grep -q ":${GRPC_PORT} "; then
    echo "ERROR: port ${GRPC_PORT} is already in use — choose another with --grpc-port" >&2
    exit 1
fi

DB_FILE="${KRAKEN_ROOT}/kraken-mtls-test-$$.db"
SERVER_LOG="/tmp/kraken-mtls-test-$$.log"

KRAKEN_TLS_CA="${CERTS_DIR}/ca.crt" \
KRAKEN_TLS_CERT="${CERTS_DIR}/server.crt" \
KRAKEN_TLS_KEY="${CERTS_DIR}/server.key" \
RUST_LOG=error \
"${SERVER_BIN}" \
    --grpc-port "${GRPC_PORT}" \
    --http-port $((GRPC_PORT + 1000)) \
    --db-path   "${DB_FILE}" \
    >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

info "Server starting (PID $SERVER_PID)…"

# Wait up to 10 s for the port to become reachable
READY=false
for i in $(seq 1 20); do
    if ss -tlnp 2>/dev/null | grep -q ":${GRPC_PORT} "; then
        READY=true; break
    fi
    sleep 0.5
done

if ! $READY || ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: server did not become ready within 10 seconds" >&2
    cat "${SERVER_LOG}" >&2
    exit 1
fi
info "Server ready on port ${GRPC_PORT}"

# ── Step 3: TLS tests ─────────────────────────────────────────────────────────
echo ""
echo "── Step 3: TLS tests ───────────────────────────────────────────────────────"

# ── Test 1: Server speaks TLS — plaintext is rejected ────────────────────────
echo ""
echo "  [1] Plaintext connection is rejected (server speaks TLS only)"
PLAIN_OUTPUT=$(printf 'GET / HTTP/1.0\r\n\r\n' | timeout 3 bash -c \
    "exec 3<>/dev/tcp/127.0.0.1/${GRPC_PORT}; cat >&3 <&0; cat <&3" 2>/dev/null || true)

# A TLS server must not echo back a plaintext HTTP response
if echo "$PLAIN_OUTPUT" | grep -qi "HTTP/"; then
    fail "Server accepted plaintext HTTP — TLS is NOT active"
else
    pass "Plaintext connection rejected (TLS enforced)"
fi

# ── Test 2: Valid CA — server cert verified ───────────────────────────────────
echo ""
echo "  [2] Server certificate verified with correct CA"
if tls_verify_server "${CERTS_DIR}/ca.crt" \
        "${CERTS_DIR}/operator.crt" "${CERTS_DIR}/operator.key"; then
    pass "Server cert verified with correct CA"
else
    fail "Server cert NOT verified with correct CA (expected: success)"
fi

# ── Test 3: Wrong CA — server cert rejected by client ────────────────────────
echo ""
echo "  [3] Server certificate rejected when client uses wrong CA"
if tls_verify_server "${CERTS_DIR}/wrong-ca.crt" \
        "${CERTS_DIR}/operator.crt" "${CERTS_DIR}/operator.key"; then
    fail "Server cert accepted with wrong CA (expected: rejected)"
else
    pass "Server cert rejected with wrong CA"
fi

# ── Test 4: No CA — server cert rejected without trust anchor ─────────────────
echo ""
echo "  [4] Server certificate rejected when client has no trust anchor"
# Use /dev/null as an empty CAfile — openssl will have no trusted CAs
NOCERT_OUTPUT=$(echo QUIT | openssl s_client \
    -connect "127.0.0.1:${GRPC_PORT}" \
    -CAfile /dev/null \
    -verify_return_error \
    2>&1 || true)

if echo "$NOCERT_OUTPUT" | grep -q "Verify return code: 0 (ok)"; then
    fail "Server cert accepted with empty trust store (expected: rejected)"
else
    pass "Server cert rejected with empty trust store"
fi

# ── Test 5: Expired server cert — rejected by client ─────────────────────────
echo ""
echo "  [5] Expired server certificate rejected by client"
EXPIRED_CERT="${CERTS_DIR}/expired-server.crt"
EXPIRED_KEY="${CERTS_DIR}/expired-server.key"

if [[ -f "$EXPIRED_CERT" ]] && ! openssl x509 -in "$EXPIRED_CERT" -noout -checkend 0 2>/dev/null; then
    # Stop the real server, start one with the expired cert
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
    sleep 0.5

    rm -f "${DB_FILE}"
    KRAKEN_TLS_CA="${CERTS_DIR}/ca.crt" \
    KRAKEN_TLS_CERT="${EXPIRED_CERT}" \
    KRAKEN_TLS_KEY="${EXPIRED_KEY}" \
    RUST_LOG=error \
    "${SERVER_BIN}" \
        --grpc-port "${GRPC_PORT}" \
        --http-port $((GRPC_PORT + 1000)) \
        --db-path   "${DB_FILE}" \
        >>"${SERVER_LOG}" 2>&1 &
    SERVER_PID=$!

    for i in $(seq 1 20); do
        ss -tlnp 2>/dev/null | grep -q ":${GRPC_PORT} " && break
        sleep 0.5
    done

    EXPIRED_OUT=$(echo QUIT | openssl s_client \
        -connect "127.0.0.1:${GRPC_PORT}" \
        -CAfile  "${CERTS_DIR}/ca.crt" \
        -verify_return_error \
        2>&1 || true)

    if echo "$EXPIRED_OUT" | grep -q "Verify return code: 0 (ok)"; then
        fail "Expired server cert accepted (expected: rejected)"
    else
        pass "Expired server cert rejected by client"
    fi

    # Restore server with valid cert
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
    sleep 0.5
    rm -f "${DB_FILE}"
    KRAKEN_TLS_CA="${CERTS_DIR}/ca.crt" \
    KRAKEN_TLS_CERT="${CERTS_DIR}/server.crt" \
    KRAKEN_TLS_KEY="${CERTS_DIR}/server.key" \
    RUST_LOG=error \
    "${SERVER_BIN}" \
        --grpc-port "${GRPC_PORT}" \
        --http-port $((GRPC_PORT + 1000)) \
        --db-path   "${DB_FILE}" \
        >>"${SERVER_LOG}" 2>&1 &
    SERVER_PID=$!
    for i in $(seq 1 20); do
        ss -tlnp 2>/dev/null | grep -q ":${GRPC_PORT} " && break
        sleep 0.5
    done
else
    skip "Expired server cert — could not generate a genuinely expired cert on this OpenSSL version"
fi

# ── Test 6: TLS version — must be TLS 1.3 ────────────────────────────────────
echo ""
echo "  [6] TLS 1.3 is negotiated (no downgrade to obsolete versions)"
PROTO=$(tls_get_protocol "${CERTS_DIR}/ca.crt")
if [[ "$PROTO" == "TLSv1.3" ]]; then
    pass "TLS 1.3 negotiated (protocol: $PROTO)"
elif [[ -n "$PROTO" ]]; then
    fail "Unexpected TLS version: $PROTO (expected TLSv1.3)"
else
    skip "Could not determine negotiated TLS version"
fi

# ── Tests 7–9: Client-cert enforcement (gRPC interceptor) ─────────────────────
#
# The require_client_cert interceptor rejects requests with no peer certificate
# by returning gRPC status UNAUTHENTICATED (16).  We probe this via curl --http2
# using a minimal gRPC-encoded request body (5-byte framing prefix + empty
# protobuf message).  Requests without a client cert must get grpc-status 16;
# requests with a valid cert must NOT get grpc-status 16 (they reach the service
# layer and get 12 UNIMPLEMENTED or another non-auth error).
#
# grpc_call CA [CLIENT_CERT CLIENT_KEY]
#   Make a gRPC POST to a well-known endpoint and print the full curl output.
grpc_call() {
    local ca_file="$1"
    local client_cert="${2:-}"
    local client_key="${3:-}"

    # 5-byte gRPC frame header for an empty message body (no compression, 0 bytes)
    local grpc_body
    grpc_body=$(printf '\x00\x00\x00\x00\x00')

    local curl_args=(
        --silent --show-error --max-time 5
        --http2 --cacert "$ca_file"
        -X POST
        -H "Content-Type: application/grpc"
        -H "TE: trailers"
        --data-binary "$grpc_body"
    )
    [[ -n "$client_cert" ]] && curl_args+=(--cert "$client_cert" --key "$client_key")

    # Target a known gRPC endpoint; the service name/method doesn't matter for
    # the interceptor check — it fires before routing.
    curl "${curl_args[@]}" \
        "https://127.0.0.1:${GRPC_PORT}/kraken.OperatorService/GetSelf" 2>&1 || true
}

# ── Test 7: No client cert → UNAUTHENTICATED ─────────────────────────────────
echo ""
echo "  [7] Client cert required — gRPC request without cert returns UNAUTHENTICATED (16)"
T7_OUT=$(grpc_call "${CERTS_DIR}/ca.crt")
if echo "$T7_OUT" | grep -q "grpc-status: 16\|grpc-status:16"; then
    pass "Request without client cert rejected with grpc-status 16 (UNAUTHENTICATED)"
elif echo "$T7_OUT" | grep -qiE "SSL|certificate|handshake|alert"; then
    # TLS layer itself rejected the connection — still means no cert = no access
    pass "Request without client cert rejected at TLS layer (no access without cert)"
else
    fail "Request without client cert was NOT rejected with UNAUTHENTICATED (output: $(echo "$T7_OUT" | head -3))"
fi

# ── Test 8: Client cert from wrong CA → rejected ──────────────────────────────
echo ""
echo "  [8] Client cert from wrong CA rejected — gRPC returns UNAUTHENTICATED (16)"
T8_OUT=$(grpc_call "${CERTS_DIR}/ca.crt" \
    "${CERTS_DIR}/rogue-operator.crt" "${CERTS_DIR}/rogue-operator.key")
# The server's CA does not trust the rogue cert; either the TLS handshake fails
# (rustls rejects it during verification) or the interceptor rejects it.
if echo "$T8_OUT" | grep -q "grpc-status: 16\|grpc-status:16"; then
    pass "Rogue client cert rejected with grpc-status 16 (UNAUTHENTICATED)"
elif echo "$T8_OUT" | grep -qiE "SSL|certificate|handshake|alert|curl.*error"; then
    pass "Rogue client cert rejected at TLS/transport layer"
else
    fail "Rogue client cert was NOT rejected (output: $(echo "$T8_OUT" | head -3))"
fi

# ── Test 9: Valid client cert → reaches service (not UNAUTHENTICATED) ─────────
echo ""
echo "  [9] Valid client cert accepted — gRPC request reaches service layer (not 16)"
T9_OUT=$(grpc_call "${CERTS_DIR}/ca.crt" \
    "${CERTS_DIR}/operator.crt" "${CERTS_DIR}/operator.key")
if echo "$T9_OUT" | grep -q "grpc-status: 16\|grpc-status:16"; then
    fail "Valid client cert incorrectly rejected with UNAUTHENTICATED (grpc-status 16)"
elif echo "$T9_OUT" | grep -qE "grpc-status"; then
    # Got a gRPC response (any other status) — interceptor passed the request through
    STATUS=$(echo "$T9_OUT" | grep -oE "grpc-status[: ]+[0-9]+" | head -1)
    pass "Valid client cert accepted — reached service layer (${STATUS})"
elif echo "$T9_OUT" | grep -qi "HTTP/2"; then
    pass "Valid client cert accepted — HTTP/2 response received from server"
else
    fail "Valid client cert did not get a gRPC response (output: $(echo "$T9_OUT" | head -3))"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL))
echo ""
echo "=== Test Summary ═══════════════════════════════════════════════════════════"
printf "  Passed : %d / %d\n" "$PASS" "$TOTAL"
printf "  Failed : %d / %d\n" "$FAIL" "$TOTAL"
printf "  Skipped: %d (not yet implemented)\n" "$SKIP"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}=== ALL ACTIVE TESTS PASSED ===${RESET}"
    exit 0
else
    echo -e "${RED}=== $FAIL TEST(S) FAILED ===${RESET}"
    exit 1
fi

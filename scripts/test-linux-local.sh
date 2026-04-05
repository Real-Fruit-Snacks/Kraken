#!/bin/bash
# Automated Linux Local Testing Script for Kraken C2
# Usage: ./scripts/test-linux-local.sh

# Don't use set -e - we want to continue on test failures

KRAKEN_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")
cd "$KRAKEN_ROOT"

echo "=== Kraken Linux Local Test Script ==="
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -f "target/release/implant" 2>/dev/null || true
    pkill -f "target/release/kraken-server" 2>/dev/null || true
    rm -f kraken.db
}
trap cleanup EXIT

# Build components
echo "[1/5] Building components..."
cargo build --release -p server -p implant-core --features "mod-shell,mod-file" 2>&1 | tail -3
echo "      Build complete"

# Start server
echo "[2/5] Starting server..."
rm -f kraken.db
RUST_LOG=info ./target/release/kraken-server &>/tmp/kraken-test.log &
SERVER_PID=$!
sleep 3

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: Server failed to start"
    cat /tmp/kraken-test.log
    exit 1
fi
echo "      Server running (PID: $SERVER_PID)"

# Start implant
echo "[3/5] Starting implant..."
KRAKEN_SERVER="http://localhost:8080" RUST_LOG=implant=info ./target/release/implant &>/tmp/implant-test.log &
IMPLANT_PID=$!
sleep 5

# Wait for registration
IMPLANT_ID=""
for i in {1..10}; do
    IMPLANT_ID=$(sqlite3 kraken.db "SELECT hex(id) FROM implants LIMIT 1;" 2>/dev/null || echo "")
    if [[ -n "$IMPLANT_ID" ]]; then
        break
    fi
    sleep 1
done

if [[ -z "$IMPLANT_ID" ]]; then
    echo "ERROR: Implant did not register"
    cat /tmp/implant-test.log
    exit 1
fi

IMPLANT_NAME=$(sqlite3 kraken.db "SELECT name FROM implants LIMIT 1;")
echo "      Implant registered: $IMPLANT_NAME"

# Run basic tests
echo "[4/5] Running basic tests..."
TASK_CLI="./target/release/task"

run_test() {
    local NAME="$1"
    local CMD="$2"
    local TIMEOUT="${3:-20}"

    echo -n "  [$NAME] "
    TASK_ID=$("$TASK_CLI" "$IMPLANT_ID" shell "$CMD" 2>&1 | grep -oP 'ID: \K[a-f0-9]+' || echo "")

    if [[ -z "$TASK_ID" ]]; then
        echo "DISPATCH_FAILED"
        return 1
    fi

    for i in $(seq 1 $TIMEOUT); do
        STATUS=$(sqlite3 kraken.db "SELECT status FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null || echo "")
        if [[ "$STATUS" == "completed" ]]; then
            RESULT=$(sqlite3 kraken.db "SELECT result_data FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null)
            EXIT_CODE=$(echo "$RESULT" | grep -oP '"exit_code":\K-?\d+' || echo "-1")
            DURATION=$(echo "$RESULT" | grep -oP '"duration_ms":\K\d+' || echo "0")
            BYTES=${#RESULT}

            if [[ "$EXIT_CODE" == "0" ]]; then
                echo "PASS (${BYTES}B, ${DURATION}ms)"
                return 0
            else
                echo "FAIL (exit=$EXIT_CODE)"
                return 1
            fi
        fi
        sleep 1
    done
    echo "TIMEOUT"
    return 1
}

PASS=0
FAIL=0

run_test "whoami" "whoami" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "hostname" "hostname" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "pwd" "pwd" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "uname" "uname -a" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "ls" "ls -la /tmp" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

# Run stress tests
echo ""
echo "[5/5] Running stress tests..."

run_test "env" "env" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "ps-aux" "ps aux" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "df" "df -h" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "proc-cpuinfo" "cat /proc/cpuinfo" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
run_test "find-tmp" "find /tmp -maxdepth 2 -type f 2>/dev/null | head -50" 30 && PASS=$((PASS+1)) || FAIL=$((FAIL+1))

# Rapid fire test
echo ""
BEFORE_TOTAL=$(sqlite3 kraken.db "SELECT COUNT(*) FROM tasks;" 2>/dev/null || echo "0")
echo "  [rapid-fire] Dispatching 10 commands..."
for i in {1..10}; do
    "$TASK_CLI" "$IMPLANT_ID" shell "echo test$i" &>/dev/null
done
sleep 25
AFTER_TOTAL=$(sqlite3 kraken.db "SELECT COUNT(*) FROM tasks;" 2>/dev/null || echo "0")
AFTER_COMPLETED=$(sqlite3 kraken.db "SELECT COUNT(*) FROM tasks WHERE status='completed';" 2>/dev/null || echo "0")
RAPID_DISPATCHED=$((AFTER_TOTAL - BEFORE_TOTAL))
# Count how many of all tasks completed vs total
echo "  [rapid-fire] $AFTER_COMPLETED/$AFTER_TOTAL completed"

if [[ "$AFTER_COMPLETED" -eq "$AFTER_TOTAL" ]]; then
    PASS=$((PASS+1))
    echo "  [rapid-fire] PASS"
else
    FAIL=$((FAIL+1))
    echo "  [rapid-fire] FAIL (some pending)"
fi

# Summary
echo ""
echo "=== Test Summary ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"

TOTAL_OUTPUT=$(sqlite3 kraken.db "SELECT SUM(length(result_data)) FROM tasks WHERE status='completed';" 2>/dev/null || echo "0")
echo "Total output: $TOTAL_OUTPUT bytes"

echo ""
if [[ "$FAIL" -eq 0 ]]; then
    echo "=== ALL TESTS PASSED ==="
    exit 0
else
    echo "=== SOME TESTS FAILED ==="
    exit 1
fi

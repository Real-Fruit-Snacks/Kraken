#!/bin/bash
# Kraken Mesh Networking Live Test Script
#
# Topology: Windows (Leaf) <--TCP--> Kali (Hub) <--HTTPS--> Server

set -e

KALI_IP="192.168.247.131"
WINDOWS_IP="192.168.247.132"
SERVER_PORT="8080"
MESH_PORT="9999"

echo "=== Kraken Mesh Networking Live Test ==="
echo ""
echo "Topology:"
echo "  [Windows Leaf] <--TCP:$MESH_PORT--> [Kali Hub] <--HTTPS:$SERVER_PORT--> [Server]"
echo ""

# Check if server binary exists
if [ ! -f target/release/server ] && [ ! -f target/debug/server ]; then
    echo "[!] Server binary not found. Building..."
    cargo build -p server
fi

SERVER_BIN="${1:-target/debug/server}"
[ -f target/release/server ] && SERVER_BIN="target/release/server"

echo "[*] Using server: $SERVER_BIN"

# Start server
echo "[*] Starting Kraken server on $KALI_IP:$SERVER_PORT..."
RUST_LOG=info $SERVER_BIN &
SERVER_PID=$!
echo "[+] Server PID: $SERVER_PID"

sleep 2

# Get server public key
echo ""
echo "[*] Server public key (set this on implants):"
echo "    Check server output or config for KRAKEN_SERVER_PUBKEY"
echo ""

echo "=== Next Steps ==="
echo ""
echo "1. On Kali (Hub implant):"
echo "   export KRAKEN_SERVER=http://$KALI_IP:$SERVER_PORT"
echo "   ./target/debug/implant"
echo ""
echo "2. On Windows (Leaf implant):"
echo "   Copy implant.exe to Windows"
echo "   Set env: KRAKEN_SERVER=http://$KALI_IP:$SERVER_PORT"
echo "   Run implant.exe"
echo ""
echo "3. In Operator TUI:"
echo "   - Wait for both implants to check in"
echo "   - Use 'mesh connect <windows-id> <kali-id> tcp $KALI_IP $MESH_PORT'"
echo "   - Set roles: 'mesh role <kali-id> hub'"
echo "   - Press 'x' to view mesh topology"
echo ""
echo "Press Ctrl+C to stop server"
wait $SERVER_PID

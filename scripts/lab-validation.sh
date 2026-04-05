#!/bin/bash
#
# Kraken Lab Validation Script
#
# Sets up and runs the external validation test suite.
# Must be run on a Windows VM with:
#   - Windows Defender enabled
#   - Administrator privileges
#   - Rust toolchain installed
#   - Isolated network (no production access)
#
# Usage: ./scripts/lab-validation.sh [options]
#
# Options:
#   --build-only     Only build, don't run tests
#   --skip-defender  Skip Windows Defender tests
#   --verbose        Enable verbose output
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
BUILD_ONLY=false
SKIP_DEFENDER=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --skip-defender)
            SKIP_DEFENDER=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}  Kraken External Validation Suite${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

# Check prerequisites
echo -e "${GREEN}[*] Checking prerequisites...${NC}"

# Check if running on Windows
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && ! -d "/mnt/c" ]]; then
    echo -e "${YELLOW}[!] Warning: Not running on Windows. Some tests will be skipped.${NC}"
fi

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}[!] Error: Cargo not found. Please install Rust.${NC}"
    exit 1
fi

# Check for admin privileges (Windows)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    if ! net session &> /dev/null; then
        echo -e "${YELLOW}[!] Warning: Not running as Administrator. Some tests require admin.${NC}"
    fi
fi

echo -e "${GREEN}[+] Prerequisites OK${NC}"
echo ""

# Build the implant
echo -e "${GREEN}[*] Building release implant...${NC}"
cd "$PROJECT_ROOT"

if $VERBOSE; then
    cargo build --release -p implant-core
else
    cargo build --release -p implant-core 2>&1 | tail -5
fi

if [ -f "target/release/implant" ] || [ -f "target/release/implant.exe" ]; then
    echo -e "${GREEN}[+] Implant built successfully${NC}"

    # Show binary size
    if [ -f "target/release/implant.exe" ]; then
        SIZE=$(stat -c%s "target/release/implant.exe" 2>/dev/null || stat -f%z "target/release/implant.exe")
    else
        SIZE=$(stat -c%s "target/release/implant" 2>/dev/null || stat -f%z "target/release/implant")
    fi
    SIZE_KB=$((SIZE / 1024))
    echo -e "    Binary size: ${SIZE_KB}KB"
else
    echo -e "${YELLOW}[!] Implant binary not found (expected on non-Windows)${NC}"
fi

echo ""

if $BUILD_ONLY; then
    echo -e "${GREEN}[+] Build complete (--build-only specified)${NC}"
    exit 0
fi

# Run external validation tests
echo -e "${GREEN}[*] Running external validation tests...${NC}"
echo ""

# Detection rate tests
if ! $SKIP_DEFENDER; then
    echo -e "${YELLOW}--- Detection Rate Tests ---${NC}"
    cargo test -p external-validation detection_rate -- --ignored --test-threads=1 --nocapture 2>&1 || true
    echo ""
fi

# Memory scan tests
echo -e "${YELLOW}--- Memory Scan Tests ---${NC}"
cargo test -p external-validation memory_scan -- --ignored --test-threads=1 --nocapture 2>&1 || true
echo ""

# ETW tests (Windows only)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || -d "/mnt/c" ]]; then
    echo -e "${YELLOW}--- ETW Validation Tests ---${NC}"
    cargo test -p external-validation etw_validation -- --ignored --test-threads=1 --nocapture 2>&1 || true
    echo ""

    echo -e "${YELLOW}--- AMSI Validation Tests ---${NC}"
    cargo test -p external-validation amsi_validation -- --ignored --test-threads=1 --nocapture 2>&1 || true
    echo ""
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Validation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Results summary:"
echo "  - Check test output above for pass/fail status"
echo "  - Detection rate tests show AV evasion effectiveness"
echo "  - Memory scan tests validate sleep mask/heap encryption"
echo "  - ETW/AMSI tests validate telemetry suppression"
echo ""
echo "For production readiness:"
echo "  1. All detection rate tests should pass (0% detection)"
echo "  2. Memory should be encrypted during sleep"
echo "  3. No ETW events should be generated"
echo "  4. AMSI scans should return clean"

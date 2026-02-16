#!/usr/bin/env bash
# =============================================================
# NetworkTraffic Analyzer - Portable Edition
# Linux / macOS Launcher
# =============================================================
# Part of a suite of security utilities.
# Runs the app directly from this folder with no installation.
# Copy the entire NetworkTrafficAnalyzerPortable/ folder to a
# USB drive and run from there.
#
# Usage:
#   ./NetworkTrafficAnalyzerPortable.sh           (GUI mode)
#   ./NetworkTrafficAnalyzerPortable.sh --cli     (CLI mode)
# =============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_EXE="$SCRIPT_DIR/App/NetworkTrafficAnalyzer/NetworkTrafficAnalyzer"
APP_PY="$SCRIPT_DIR/App/NetworkTrafficAnalyzer/main.py"

# Check for Python 3 (needed only if binary not found)
find_python() {
    if command -v python3 &>/dev/null; then
        echo "python3"
    elif command -v python &>/dev/null; then
        echo "python"
    else
        echo ""
    fi
}

echo "============================================"
echo "  NetworkTraffic Analyzer"
echo "  Portable Edition"
echo "============================================"
echo ""

# Prefer compiled binary; fall back to Python source
if [ -x "$APP_EXE" ]; then
    TARGET="$APP_EXE"
    echo "Running compiled binary..."
elif [ -f "$APP_PY" ]; then
    PYTHON=$(find_python)
    if [ -z "$PYTHON" ]; then
        echo "Error: Python 3 is required but not found."
        exit 1
    fi
    TARGET="$PYTHON $APP_PY"
    echo "Running from source with $PYTHON..."
else
    echo "Error: Application not found in App/NetworkTrafficAnalyzer/"
    exit 1
fi

echo "Note: Packet capture requires root/sudo privileges."
echo ""

# Elevate to root for raw socket access
if [ "$(id -u)" -ne 0 ]; then
    echo "Elevating to root for raw socket access..."

    # Try pkexec first (graphical password prompt, like Windows UAC)
    if command -v pkexec &>/dev/null && [ -n "$DISPLAY" ]; then
        pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" $TARGET "$@"
    else
        # Fall back to sudo in terminal
        sudo --preserve-env=DISPLAY,XAUTHORITY,HOME $TARGET "$@"
    fi
else
    $TARGET "$@"
fi

#!/usr/bin/env bash
# =============================================================
# Local Security Tool - Portable Edition
# Linux/Mac Launcher
# =============================================================
# Integrated Security Suite:
#   - Network Port Scanner
#   - Network Traffic Analyzer (Real-Time Monitoring)
#
# Runs directly from this folder. No installation required.
# Copy the entire folder to a USB drive and run from there.
#
# Note: Packet capture may require sudo/admin privileges.
# =============================================================

set -e

echo "============================================"
echo "        LOCAL SECURITY TOOL"
echo "        Portable Edition"
echo "============================================"
echo "  Integrated Modules:"
echo "    [1] Network Port Scanner"
echo "    [2] Network Traffic Analyzer"
echo "============================================"
echo ""

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP_EXE="$ROOT_DIR/App/LocalSecurityTool/LocalSecurityTool"
APP_PY="$ROOT_DIR/App/suite_main.py"

# Prefer compiled binary (if present)
if [ -f "$APP_EXE" ] && [ -x "$APP_EXE" ]; then
  echo "Running compiled Local Security Tool..."
  "$APP_EXE" "$@"
  exit 0
fi

# Fall back to Python source
if [ ! -f "$APP_PY" ]; then
  echo "Error: Local Security Tool entry file not found."
  echo ""
  echo "Expected:"
  echo "  EXE: $APP_EXE"
  echo "  PY : $APP_PY"
  echo ""
  echo "Make sure the folder structure is intact:"
  echo "  LocalSecurityTool/"
  echo "    LocalSecurityTool.sh"
  echo "    App/suite_main.py"
  exit 1
fi

echo "Running from Python source..."
echo ""

# Prefer python3, fall back to python
if command -v python3 >/dev/null 2>&1; then
  python3 "$APP_PY" "$@"
  exit 0
fi

if command -v python >/dev/null 2>&1; then
  python "$APP_PY" "$@"
  exit 0
fi

echo "Error: Python 3 is required but not found in PATH."
echo "Install Python 3 and try again."
exit 1
#!/usr/bin/env bash
# =============================================================
# Local Security Tool - Portable Edition
# Linux/macOS Launcher
# =============================================================
# Integrated Security Suite:
#   - Network Port Scanner
#   - Network Traffic Analyzer (Real-Time Monitoring)
#
# Runs directly from this folder. No installation required.
# Copy the entire folder to a USB drive and run from there.
#
# Note: Packet capture and raw socket access require root/sudo privileges.
# =============================================================

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

# ── Determine what to run ──────────────────────────────────────
if [ -f "$APP_EXE" ] && [ -x "$APP_EXE" ]; then
  echo "Running compiled Local Security Tool..."
  TARGET="$APP_EXE"
elif [ -f "$APP_PY" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
  else
    echo "Error: Python 3 is required but not found in PATH."
    echo "Install Python 3 and try again."
    exit 1
  fi
  echo "Running from Python source with $PYTHON..."
  TARGET="$PYTHON $APP_PY"
else
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

echo "Note: Raw socket / port scan operations require root/sudo privileges."
echo ""

# ── Privilege elevation ────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "Elevating to root for privileged operations..."

  # Resolve XAUTHORITY if not set (common when launched from a .desktop file)
  if [ -z "$XAUTHORITY" ]; then
    if [ -f "$HOME/.Xauthority" ]; then
      XAUTHORITY="$HOME/.Xauthority"
    else
      XAUTHORITY=$(ls /run/user/"$(id -u)"/.mutter-Xwaylandauth.* 2>/dev/null | head -1)
    fi
  fi

  # Try pkexec first (graphical password prompt, like Windows UAC)
  if command -v pkexec &>/dev/null && [ -n "$DISPLAY" ]; then
    xhost +SI:localuser:root 2>/dev/null || true
    pkexec env DISPLAY="$DISPLAY" XAUTHORITY="$XAUTHORITY" $TARGET "$@"
  else
    # Fall back to sudo in terminal
    sudo --preserve-env=DISPLAY,XAUTHORITY,HOME $TARGET "$@"
  fi
else
  $TARGET "$@"
fi

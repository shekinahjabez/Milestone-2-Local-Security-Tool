#!/usr/bin/env bash
# Elevated launcher for Local Security Tool
# Grants root access to current X display, then runs app via pkexec

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PY="$SCRIPT_DIR/App/suite_main.py"

xhost +SI:localuser:root
pkexec env DISPLAY="$DISPLAY" python3 "$APP_PY"

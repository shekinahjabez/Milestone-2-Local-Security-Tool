#!/usr/bin/env bash
# =============================================================
# Local Security Tool - macOS Launcher
# =============================================================
# Double-click this file in Finder to launch the tool.
#
# macOS opens .command files in Terminal automatically.
# On first run, right-click -> Open to bypass Gatekeeper.
# =============================================================
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/LocalSecurityTool.sh" "$@"

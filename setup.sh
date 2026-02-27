#!/usr/bin/env bash
# =============================================================
# Local Security Tool - Setup Script
#
# Run once after copying the tool to a new location on Linux.
# Writes the correct absolute paths into LocalSecurityTool.desktop
# so it can be launched by double-clicking.
#
# macOS and Windows do not need this script:
#   Windows -- LocalSecurityTool.bat     (uses %~dp0)
#   macOS   -- LocalSecurityTool.command (uses BASH_SOURCE[0])
# =============================================================

SETUP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s)"

echo "============================================"
echo "        LOCAL SECURITY TOOL"
echo "        Setup / Install"
echo "============================================"
echo "Detected OS : $OS"
echo "Tool location: $SETUP_DIR"
echo ""

if [ "$OS" = "Linux" ]; then

  DESKTOP_FILE="$SETUP_DIR/LocalSecurityTool.desktop"

  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Local Security Tool
Comment=Integrated Port Scanner and Network Traffic Analyzer - Portable Edition
Exec=$SETUP_DIR/LocalSecurityTool.sh
Path=$SETUP_DIR
Terminal=false
Categories=Network;Security;
StartupNotify=true
EOF

  chmod +x "$SETUP_DIR/LocalSecurityTool.sh"
  chmod +x "$DESKTOP_FILE"
  echo "[OK] LocalSecurityTool.desktop updated with correct paths."
  echo "[OK] Launchers marked as executable."

  echo ""
  read -r -p "Install shortcut to application menu (~/.local/share/applications/)? [y/N] " REPLY
  if [[ "$REPLY" =~ ^[Yy]$ ]]; then
    mkdir -p "$HOME/.local/share/applications"
    cp "$DESKTOP_FILE" "$HOME/.local/share/applications/LocalSecurityTool.desktop"
    echo "[OK] Shortcut installed to application menu."
  else
    echo "[--] Skipped application menu install."
  fi

else
  echo "Note: setup.sh is only needed on Linux."
  echo "      Your platform ($OS) requires no setup."
  echo "      Just double-click the launcher for your OS."
fi

echo ""
echo "[Done]"
echo "============================================"

#!/usr/bin/env python3
"""
NetworkTraffic Analyzer - PortableApps Launcher
=================================================
Portable application entry point following PortableApps.com Format 3.9.

Directory Layout:
    NetworkTrafficAnalyzerPortable/
    ├── App/
    │   ├── AppInfo/appinfo.ini            Metadata and version info
    │   ├── DefaultData/                   Template copied to Data/ on first run
    │   └── NetworkTrafficAnalyzer/        Application code and binary
    ├── Data/                              User data (logs, settings) - portable
    └── Other/                             Help docs and source code

Launcher Behavior (per PortableApps.com spec):
    1. Resolve PORTABLE_ROOT as the NetworkTrafficAnalyzerPortable/ directory.
    2. Check if Data/ exists. If not, copy from App/DefaultData/.
    3. Set NTA_DATA_DIR so all modules write to Data/.
    4. Launch the GUI (or CLI with --cli flag).
    5. On exit, no cleanup needed - nothing written outside PORTABLE_ROOT.

Security Notes:
    - No system files, registry, or environment variables are modified.
    - All data is stored inside NetworkTrafficAnalyzerPortable/Data/.
    - The application runs entirely offline.
    - Scapy requires root/admin privileges for raw socket access;
      the app checks and reports this gracefully.

Part of a suite of security utilities.
"""

import sys
import os
import shutil

# ---------------------------------------------------------------------------
# Path Resolution
# ---------------------------------------------------------------------------
# Resolve paths for both normal Python execution and PyInstaller binaries.
# PyInstaller extracts bundled files to a temp _MEIPASS directory, but
# user data must go to the portable Data/ folder, never _MEIPASS.

if getattr(sys, 'frozen', False):
    # Compiled binary: executable lives in App/NetworkTrafficAnalyzer/
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
    BUNDLE_DIR = sys._MEIPASS
    sys.path.insert(0, BUNDLE_DIR)
else:
    # Source script: main.py lives in App/NetworkTrafficAnalyzer/
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR
    sys.path.insert(0, APP_DIR)

# Navigate up to the portable root:
# App/NetworkTrafficAnalyzer/ -> App/ -> NetworkTrafficAnalyzerPortable/
PORTABLE_ROOT = os.path.dirname(os.path.dirname(APP_DIR))
DATA_DIR = os.path.join(PORTABLE_ROOT, "Data")
DEFAULT_DATA_DIR = os.path.join(PORTABLE_ROOT, "App", "DefaultData")


# ---------------------------------------------------------------------------
# PortableApps Launcher: Data Directory Initialization
# ---------------------------------------------------------------------------
def initialize_data_directory():
    """
    Ensure the Data/ directory exists with required subdirectories.

    Per PortableApps.com spec: if Data/ is missing (e.g., first run or
    user deleted it), copy the template from App/DefaultData/.
    This lets users reset to defaults by simply deleting Data/.
    """
    if not os.path.exists(DATA_DIR):
        if os.path.exists(DEFAULT_DATA_DIR):
            shutil.copytree(DEFAULT_DATA_DIR, DATA_DIR)
        else:
            # DefaultData missing too - create minimal structure
            os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
            os.makedirs(os.path.join(DATA_DIR, "settings"), exist_ok=True)
    else:
        # Data/ exists but ensure subdirectories are present
        os.makedirs(os.path.join(DATA_DIR, "logs"), exist_ok=True)
        os.makedirs(os.path.join(DATA_DIR, "settings"), exist_ok=True)


# ---------------------------------------------------------------------------
# Export paths for other modules
# ---------------------------------------------------------------------------
initialize_data_directory()
os.environ["NTA_DATA_DIR"] = DATA_DIR
os.environ["NTA_APP_DIR"] = APP_DIR
os.environ["NTA_PORTABLE_ROOT"] = PORTABLE_ROOT


# ---------------------------------------------------------------------------
# Application Modes
# ---------------------------------------------------------------------------
def run_cli():
    """Minimal CLI mode for environments without a display."""
    from core.sniffer import CaptureEngine, SCAPY_AVAILABLE

    if not SCAPY_AVAILABLE:
        print("Error: Scapy is not installed.")
        print("Install it with:  pip install scapy")
        sys.exit(1)

    print("=" * 60)
    print("  NetworkTraffic Analyzer - Portable Edition (CLI)")
    print("=" * 60)
    print(f"  Data directory: {DATA_DIR}")
    print("=" * 60)

    # Prompt for optional filters
    protocol = input("\nFilter by protocol (tcp/udp/icmp or Enter for all): ").strip()
    port = input("Filter by port (or Enter for any): ").strip()

    engine = CaptureEngine()

    def on_packet(line):
        print(line)

    try:
        engine.start(protocol=protocol, port=port, callback=on_packet)
        print("\nCapture started... Press Ctrl+C to stop.\n")
        # Keep main thread alive while capture runs
        while engine.running:
            pass
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        engine.stop()
        print("\nCapture stopped.")


def run_gui():
    """Launch the Tkinter GUI."""
    from gui.app import main
    main()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        run_cli()
    else:
        run_gui()

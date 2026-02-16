"""
NetworkTraffic Analyzer - GUI Module
======================================
Tkinter-based graphical interface styled after the SecureKit template.

Visual Design (from SecureKit Template):
  - Background: Light neutral (white / #f5f5f5)
  - Primary accent: Blue (#007bff) for buttons and highlights
  - Text: Dark gray (#333)
  - Typography: Sans-serif (system default), bold headings
  - Buttons: Rounded feel, solid blue fill, hover darkening
  - Layout: Centered sections with generous padding

PortableApps.com Compliance:
  - All user data writes go to NetworkTrafficAnalyzerPortable/Data/logs/
  - No system files, registry, or temp dirs are modified.
  - The Data/ directory is auto-created from DefaultData/ if missing.

Part of a suite of security utilities.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import sys
from datetime import datetime

# Add parent directory to path so we can import the core module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.sniffer import CaptureEngine, SCAPY_AVAILABLE


# ---------------------------------------------------------------------------
# Color Constants (SecureKit Template)
# ---------------------------------------------------------------------------
PRIMARY_COLOR = "#007bff"
PRIMARY_HOVER = "#0056b3"
BG_COLOR = "#f5f5f5"
WHITE = "#ffffff"
TEXT_COLOR = "#333333"
LIGHT_GRAY = "#e0e0e0"
HEADER_BG = "#1a1a2e"
HEADER_FG = "#ffffff"
SUCCESS_GREEN = "#28a745"
ERROR_RED = "#dc3545"
WARNING_YELLOW = "#ffc107"


class NetworkTrafficAnalyzerApp:
    """
    Main application window for the NetworkTraffic Analyzer.

    Sections (following the SecureKit template pattern):
      1. Header   - App title and tagline
      2. Filters  - Protocol and port input fields
      3. Controls - Start/Stop capture buttons
      4. Display  - Real-time scrolling packet log
      5. Stats    - Live packet count by protocol
      6. Footer   - Attribution line
    """

    def __init__(self, root):
        self.root = root
        self.root.title("NetworkTraffic Analyzer - Portable Edition")
        self.root.geometry("960x720")
        self.root.minsize(760, 560)
        self.root.configure(bg=BG_COLOR)

        # Capture engine instance
        self.engine = CaptureEngine()
        self.packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

        # PortableApps.com path resolution:
        # Logs write to NetworkTrafficAnalyzerPortable/Data/logs/
        # (never outside the portable root). NTA_DATA_DIR is set by the
        # launcher in main.py to point to the correct Data/ folder.
        self.data_dir = os.environ.get("NTA_DATA_DIR", "")
        if not self.data_dir:
            # Fallback: derive from this file's location
            # gui/app.py -> NetworkTrafficAnalyzer/ -> App/ -> Portable root/
            portable_root = os.path.dirname(
                os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                )
            )
            self.data_dir = os.path.join(portable_root, "Data")

        self.log_dir = os.path.join(self.data_dir, "logs")
        os.makedirs(self.log_dir, exist_ok=True)

        self._build_ui()
        self._check_scapy()

        # Clean shutdown when window is closed
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------------------------------------------------------------------
    # UI Construction
    # -------------------------------------------------------------------
    def _build_ui(self):
        """Assemble all UI sections."""
        self._build_header()
        self._build_filter_section()
        self._build_controls()
        self._build_display()
        self._build_stats()
        self._build_footer()

    def _build_header(self):
        """Header bar with app title and tagline."""
        header = tk.Frame(self.root, bg=HEADER_BG, pady=16)
        header.pack(fill=tk.X)

        title = tk.Label(
            header,
            text="NetworkTraffic Analyzer",
            font=("Helvetica", 22, "bold"),
            bg=HEADER_BG,
            fg=HEADER_FG,
        )
        title.pack()

        tagline = tk.Label(
            header,
            text="Real-Time Packet Capture \u2022 Portable Edition",
            font=("Helvetica", 11),
            bg=HEADER_BG,
            fg="#aaaaaa",
        )
        tagline.pack()

    def _build_filter_section(self):
        """
        Filter section with protocol dropdown and port input.
        Matches the SecureKit 'section' card style.
        """
        section = tk.Frame(self.root, bg=WHITE, padx=24, pady=16)
        section.pack(fill=tk.X, padx=24, pady=(16, 4))

        heading = tk.Label(
            section,
            text="Capture Filters",
            font=("Helvetica", 14, "bold"),
            bg=WHITE,
            fg=TEXT_COLOR,
            anchor="w",
        )
        heading.pack(fill=tk.X, pady=(0, 8))

        desc = tk.Label(
            section,
            text="Select a protocol and/or port to filter traffic. "
                 "Leave blank to capture all packets.",
            font=("Helvetica", 10),
            bg=WHITE,
            fg="#666666",
            anchor="w",
        )
        desc.pack(fill=tk.X, pady=(0, 12))

        # Input row
        input_frame = tk.Frame(section, bg=WHITE)
        input_frame.pack(fill=tk.X)

        # Protocol dropdown
        tk.Label(
            input_frame,
            text="Protocol:",
            font=("Helvetica", 10, "bold"),
            bg=WHITE,
            fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.protocol_var = tk.StringVar(value="All")
        protocol_menu = ttk.Combobox(
            input_frame,
            textvariable=self.protocol_var,
            values=["All", "TCP", "UDP", "ICMP"],
            state="readonly",
            width=10,
        )
        protocol_menu.pack(side=tk.LEFT, padx=(0, 20))

        # Port input
        tk.Label(
            input_frame,
            text="Port:",
            font=("Helvetica", 10, "bold"),
            bg=WHITE,
            fg=TEXT_COLOR,
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.port_var = tk.StringVar()
        port_entry = tk.Entry(
            input_frame,
            textvariable=self.port_var,
            width=10,
            font=("Helvetica", 10),
            relief=tk.SOLID,
            borderwidth=1,
        )
        port_entry.pack(side=tk.LEFT)

    def _build_controls(self):
        """Start / Stop / Export buttons styled with blue theme."""
        section = tk.Frame(self.root, bg=BG_COLOR, pady=8)
        section.pack(fill=tk.X, padx=24)

        btn_frame = tk.Frame(section, bg=BG_COLOR)
        btn_frame.pack()

        self.start_btn = tk.Button(
            btn_frame,
            text="Start Capture",
            font=("Helvetica", 11, "bold"),
            bg=PRIMARY_COLOR,
            fg=WHITE,
            activebackground=PRIMARY_HOVER,
            activeforeground=WHITE,
            relief=tk.FLAT,
            padx=20,
            pady=6,
            cursor="hand2",
            command=self._start_capture,
        )
        self.start_btn.pack(side=tk.LEFT, padx=6)

        self.stop_btn = tk.Button(
            btn_frame,
            text="Stop Capture",
            font=("Helvetica", 11, "bold"),
            bg=ERROR_RED,
            fg=WHITE,
            activebackground="#a71d2a",
            activeforeground=WHITE,
            relief=tk.FLAT,
            padx=20,
            pady=6,
            cursor="hand2",
            state=tk.DISABLED,
            command=self._stop_capture,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=6)

        self.export_btn = tk.Button(
            btn_frame,
            text="Export Log",
            font=("Helvetica", 11),
            bg=SUCCESS_GREEN,
            fg=WHITE,
            activebackground="#1e7e34",
            activeforeground=WHITE,
            relief=tk.FLAT,
            padx=20,
            pady=6,
            cursor="hand2",
            command=self._export_log,
        )
        self.export_btn.pack(side=tk.LEFT, padx=6)

    def _build_display(self):
        """Scrolling text area for real-time packet output."""
        section = tk.Frame(self.root, bg=WHITE, padx=24, pady=16)
        section.pack(fill=tk.BOTH, expand=True, padx=24, pady=(4, 4))

        heading = tk.Label(
            section,
            text="Live Packet Feed",
            font=("Helvetica", 14, "bold"),
            bg=WHITE,
            fg=TEXT_COLOR,
            anchor="w",
        )
        heading.pack(fill=tk.X, pady=(0, 8))

        self.output_text = scrolledtext.ScrolledText(
            section,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground=WHITE,
            relief=tk.FLAT,
            borderwidth=0,
            state=tk.DISABLED,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Color tags for different protocols
        self.output_text.tag_configure("tcp", foreground="#569cd6")
        self.output_text.tag_configure("udp", foreground="#4ec9b0")
        self.output_text.tag_configure("icmp", foreground="#ce9178")
        self.output_text.tag_configure("error", foreground="#f44747")
        self.output_text.tag_configure("info", foreground="#608b4e")

    def _build_stats(self):
        """Live statistics bar showing packet counts by protocol."""
        section = tk.Frame(self.root, bg=WHITE, padx=24, pady=10)
        section.pack(fill=tk.X, padx=24, pady=(0, 4))

        self.stats_labels = {}
        stats_frame = tk.Frame(section, bg=WHITE)
        stats_frame.pack()

        for proto in ("TCP", "UDP", "ICMP", "Other"):
            lbl = tk.Label(
                stats_frame,
                text=f"{proto}: 0",
                font=("Helvetica", 10, "bold"),
                bg=WHITE,
                fg=TEXT_COLOR,
                padx=16,
            )
            lbl.pack(side=tk.LEFT)
            self.stats_labels[proto] = lbl

    def _build_footer(self):
        """Footer with attribution."""
        footer = tk.Frame(self.root, bg=HEADER_BG, pady=8)
        footer.pack(fill=tk.X, side=tk.BOTTOM)

        tk.Label(
            footer,
            text="Group 4 \u2022 MO-IT142 - Security Script Programming",
            font=("Helvetica", 9),
            bg=HEADER_BG,
            fg="#888888",
        ).pack()

    # -------------------------------------------------------------------
    # Scapy Availability Check
    # -------------------------------------------------------------------
    def _check_scapy(self):
        """Warn the user at startup if Scapy is missing."""
        if not SCAPY_AVAILABLE:
            self._append_output(
                "[WARNING] Scapy is not installed.\n"
                "Install it with:  pip install scapy\n"
                "Then restart the application.\n",
                tag="error",
            )

    # -------------------------------------------------------------------
    # Capture Actions
    # -------------------------------------------------------------------
    def _start_capture(self):
        """Validate inputs and start the capture engine."""
        protocol = self.protocol_var.get()
        if protocol == "All":
            protocol = ""

        port = self.port_var.get().strip()

        try:
            self.engine.start(
                protocol=protocol.lower(),
                port=port,
                callback=self._on_packet,
            )
        except (RuntimeError, ValueError) as e:
            messagebox.showerror("Filter Error", str(e))
            return

        # Update UI state
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self._update_stats()

        filter_desc = f"Protocol={protocol or 'All'}, Port={port or 'Any'}"
        self._append_output(
            f"Capture started... ({filter_desc})\n", tag="info"
        )

    def _stop_capture(self):
        """Stop the running capture."""
        self.engine.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self._append_output("Capture stopped.\n", tag="info")

    def _on_packet(self, line):
        """
        Callback invoked from the capture thread for each packet.
        Uses root.after() to safely update the GUI from the main thread.
        """
        self.root.after(0, self._display_packet, line)

    def _display_packet(self, line):
        """Append a formatted packet line to the display area."""
        # Determine tag color by protocol keyword
        tag = "tcp"
        if "UDP" in line:
            tag = "udp"
        elif "ICMP" in line:
            tag = "icmp"
        elif "[ERROR]" in line:
            tag = "error"

        # Update per-protocol counter
        for proto in ("TCP", "UDP", "ICMP"):
            if proto in line:
                self.packet_count[proto] += 1
                break
        else:
            if "[ERROR]" not in line and "[WARNING]" not in line:
                self.packet_count["Other"] += 1

        self._append_output(line + "\n", tag=tag)
        self._update_stats()

    def _append_output(self, text, tag=None):
        """Append text to the scrolled output area."""
        self.output_text.config(state=tk.NORMAL)
        if tag:
            self.output_text.insert(tk.END, text, tag)
        else:
            self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def _update_stats(self):
        """Refresh the stats labels with current counts."""
        for proto, label in self.stats_labels.items():
            label.config(text=f"{proto}: {self.packet_count[proto]}")

    # -------------------------------------------------------------------
    # Log Export (writes only to Data/logs/ per PortableApps convention)
    # -------------------------------------------------------------------
    def _export_log(self):
        """Save captured output to a timestamped file in Data/logs/."""
        content = self.output_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Export", "Nothing to export yet.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{timestamp}.log"
        filepath = os.path.join(self.log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        messagebox.showinfo(
            "Export Successful",
            f"Log saved to:\n{filepath}"
        )

    # -------------------------------------------------------------------
    # Shutdown
    # -------------------------------------------------------------------
    def _on_close(self):
        """Ensure capture stops before the window closes."""
        if self.engine.running:
            self.engine.stop()
        self.root.destroy()


def main():
    """Entry point for the GUI application."""
    root = tk.Tk()
    NetworkTrafficAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

"""
NetworkTraffic Analyzer - Packet Sniffer Module
=================================================
Handles real-time packet capture using Scapy's sniff() function.
Supports filtering by protocol (TCP, UDP, ICMP) and port number.
All captured data stays in-memory or in the portable Data/ folder.

Part of a suite of security utilities.
"""

import threading
import time
from datetime import datetime

# Attempt to import Scapy; flag availability for graceful error handling
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Filter Builder
# ---------------------------------------------------------------------------
def build_bpf_filter(protocol="", port=""):
    """
    Build a Berkeley Packet Filter (BPF) string from user-supplied
    protocol and port values.

    Args:
        protocol: One of 'tcp', 'udp', 'icmp', or '' (all).
        port:     A port number string, or '' (any port).

    Returns:
        A BPF filter string suitable for Scapy's sniff().

    Raises:
        ValueError: If the protocol name or port number is invalid.
    """
    parts = []
    protocol = protocol.strip().lower()
    port = port.strip()

    # Validate and add protocol filter
    valid_protocols = ("tcp", "udp", "icmp", "")
    if protocol not in valid_protocols:
        raise ValueError(
            f"Invalid protocol '{protocol}'. "
            f"Please enter TCP, UDP, or ICMP."
        )
    if protocol:
        parts.append(protocol)

    # Validate and add port filter (ICMP has no ports)
    if port:
        if protocol == "icmp":
            raise ValueError("ICMP does not use ports. Remove the port filter.")
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"Invalid port '{port}'. Enter a number between 1 and 65535."
            )
        parts.append(f"port {port_num}")

    return " and ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Packet Formatter
# ---------------------------------------------------------------------------
def format_packet(packet):
    """
    Extract and format key details from a captured packet.

    Returns a dict with: timestamp, source IP, destination IP,
    protocol, source port, destination port, and a brief summary.
    """
    details = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "Other",
        "src_port": "",
        "dst_port": "",
        "summary": "",
    }

    # Extract IP-layer addresses
    if packet.haslayer(IP):
        details["src_ip"] = packet[IP].src
        details["dst_ip"] = packet[IP].dst

    # Identify protocol and extract port information
    if packet.haslayer(TCP):
        details["protocol"] = "TCP"
        details["src_port"] = str(packet[TCP].sport)
        details["dst_port"] = str(packet[TCP].dport)
        flags = str(packet[TCP].flags)
        details["summary"] = f"Flags: {flags}"
    elif packet.haslayer(UDP):
        details["protocol"] = "UDP"
        details["src_port"] = str(packet[UDP].sport)
        details["dst_port"] = str(packet[UDP].dport)
        details["summary"] = f"Len: {len(packet[UDP].payload)} bytes"
    elif packet.haslayer(ICMP):
        details["protocol"] = "ICMP"
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        details["summary"] = f"Type: {icmp_type}, Code: {icmp_code}"
    else:
        details["summary"] = packet.summary()

    return details


def format_packet_line(details):
    """
    Format a packet details dict into a single display line.

    Output format:
        [Timestamp] PROTOCOL | SRC: IP:PORT | DST: IP:PORT | Summary
    """
    src = details["src_ip"]
    if details["src_port"]:
        src += f":{details['src_port']}"

    dst = details["dst_ip"]
    if details["dst_port"]:
        dst += f":{details['dst_port']}"

    return (
        f"[{details['timestamp']}] {details['protocol']} | "
        f"SRC: {src} | DST: {dst} | {details['summary']}"
    )


# ---------------------------------------------------------------------------
# Capture Engine
# ---------------------------------------------------------------------------
class CaptureEngine:
    """
    Manages the packet capture lifecycle in a background thread.

    Attributes:
        running:   Boolean flag controlling the sniff loop.
        callback:  Function called with each formatted packet line.
        packets:   List of all captured packet detail dicts.
    """

    def __init__(self):
        self.running = False
        self.callback = None
        self.packets = []
        self._thread = None

    def start(self, protocol="", port="", callback=None):
        """
        Begin capturing packets in a background thread.

        Args:
            protocol: Protocol filter string (tcp/udp/icmp or empty).
            port:     Port filter string (number or empty).
            callback: Function(str) called with each formatted line.

        Raises:
            RuntimeError: If Scapy is not installed.
            ValueError:   If filter parameters are invalid.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Please install it with:\n"
                "  pip install scapy\n"
                "Then restart the application."
            )

        bpf_filter = build_bpf_filter(protocol, port)
        self.running = True
        self.callback = callback
        self.packets = []

        # Suppress Scapy's verbose output
        conf.verb = 0

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(bpf_filter,),
            daemon=True,
        )
        self._thread.start()

    def _capture_loop(self, bpf_filter):
        """
        Internal sniffing loop. Runs in a daemon thread and processes
        packets one at a time using Scapy's sniff() with a callback.
        """
        try:
            sniff(
                filter=bpf_filter if bpf_filter else None,
                prn=self._process_packet,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except PermissionError:
            if self.callback:
                self.callback(
                    "[ERROR] Permission denied. Run with administrator/"
                    "root privileges to capture packets."
                )
        except Exception as e:
            if self.callback:
                self.callback(f"[ERROR] Capture failed: {e}")
        finally:
            self.running = False

    def _process_packet(self, packet):
        """Format a single packet and send it to the callback."""
        details = format_packet(packet)
        self.packets.append(details)
        line = format_packet_line(details)
        if self.callback:
            self.callback(line)

    def stop(self):
        """Signal the capture thread to stop."""
        self.running = False

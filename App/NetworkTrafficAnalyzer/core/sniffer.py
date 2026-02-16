"""NetworkTraffic Analyzer - Packet capture module using Scapy."""

import threading
import time
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def build_bpf_filter(protocol="", port=""):
    """Build a BPF filter string from protocol and port values."""
    parts = []
    protocol = protocol.strip().lower()
    port = port.strip()

    valid_protocols = ("tcp", "udp", "icmp", "")
    if protocol not in valid_protocols:
        raise ValueError(
            f"Invalid protocol '{protocol}'. Please enter TCP, UDP, or ICMP."
        )
    if protocol:
        parts.append(protocol)

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


# Lookup tables for human-readable packet descriptions

TCP_FLAG_NAMES = {
    "S":   "SYN (Connection request)",
    "SA":  "SYN-ACK (Connection accepted)",
    "A":   "ACK",
    "PA":  "PSH-ACK (Data push)",
    "FA":  "FIN-ACK (Connection closing)",
    "F":   "FIN (Connection closing)",
    "R":   "RST (Connection reset)",
    "RA":  "RST-ACK (Connection reset)",
    "FPA": "FIN-PSH-ACK (Final data + close)",
    "SE":  "SYN-ECE (ECN capable)",
    "SEC": "SYN-ECE-CWR",
}

ICMP_TYPE_NAMES = {
    (0, 0):  "Echo Reply (Pong)",
    (3, 0):  "Destination Network Unreachable",
    (3, 1):  "Destination Host Unreachable",
    (3, 2):  "Protocol Unreachable",
    (3, 3):  "Port Unreachable",
    (3, 4):  "Fragmentation Needed",
    (3, 6):  "Destination Network Unknown",
    (3, 13): "Communication Administratively Filtered",
    (5, 0):  "Redirect (Network)",
    (5, 1):  "Redirect (Host)",
    (8, 0):  "Echo Request (Ping)",
    (11, 0): "TTL Expired in Transit",
    (11, 1): "Fragment Reassembly Time Exceeded",
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submit", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-Browser",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _port_label(port_num):
    """Return service name for a port, or empty string."""
    name = WELL_KNOWN_PORTS.get(port_num)
    return f" ({name})" if name else ""


def format_packet(packet):
    """Extract key details from a captured packet into a dict."""
    details = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "Other",
        "src_port": "",
        "dst_port": "",
        "summary": "",
    }

    if packet.haslayer(IP):
        details["src_ip"] = packet[IP].src
        details["dst_ip"] = packet[IP].dst

    if packet.haslayer(TCP):
        details["protocol"] = "TCP"
        details["src_port"] = str(packet[TCP].sport)
        details["dst_port"] = str(packet[TCP].dport)
        flags = str(packet[TCP].flags)
        flag_desc = TCP_FLAG_NAMES.get(flags, f"Flags: {flags}")
        svc = _port_label(packet[TCP].dport) or _port_label(packet[TCP].sport)
        details["summary"] = f"{flag_desc}{svc}"
    elif packet.haslayer(UDP):
        details["protocol"] = "UDP"
        details["src_port"] = str(packet[UDP].sport)
        details["dst_port"] = str(packet[UDP].dport)
        payload_len = len(packet[UDP].payload)
        svc = _port_label(packet[UDP].dport) or _port_label(packet[UDP].sport)
        details["summary"] = f"{payload_len} bytes{svc}"
    elif packet.haslayer(ICMP):
        details["protocol"] = "ICMP"
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        desc = ICMP_TYPE_NAMES.get(
            (icmp_type, icmp_code), f"Type {icmp_type}, Code {icmp_code}"
        )
        details["summary"] = desc
    else:
        details["summary"] = packet.summary()

    return details


def format_packet_line(details):
    """Format packet details dict into a single display line."""
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


class CaptureEngine:
    """Manages packet capture in a background daemon thread."""

    def __init__(self):
        self.running = False
        self.callback = None
        self.packets = []
        self._thread = None

    def start(self, protocol="", port="", callback=None):
        """Start capturing packets with optional filters."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Please install it with:\n"
                "  pip install scapy\nThen restart the application."
            )

        bpf_filter = build_bpf_filter(protocol, port)
        self.running = True
        self.callback = callback
        self.packets = []
        conf.verb = 0

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(bpf_filter,),
            daemon=True,
        )
        self._thread.start()

    def _capture_loop(self, bpf_filter):
        """Sniff loop running in daemon thread."""
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
                    "[ERROR] Permission denied. Run with admin/root privileges."
                )
        except Exception as e:
            if self.callback:
                self.callback(f"[ERROR] Capture failed: {e}")
        finally:
            self.running = False

    def _process_packet(self, packet):
        """Format a packet and send to callback."""
        details = format_packet(packet)
        self.packets.append(details)
        line = format_packet_line(details)
        if self.callback:
            self.callback(line)

    def stop(self):
        """Signal the capture thread to stop."""
        self.running = False

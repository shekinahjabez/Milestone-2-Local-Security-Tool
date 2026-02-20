# Local Security Tool (Portable Edition)

Local Security Tool is an integrated security application developed for  
**MO-IT142 Security Script Programming – Milestone 2**.

This portable suite combines:

- 🔎 Network Port Scanning
- 📡 Real-Time Network Traffic Monitoring
- 🧾 Logging & Audit Trail

The tool demonstrates modular architecture by integrating active scanning and passive monitoring into a unified local system security utility.

---

## 🔐 Features

### Network Port Scanner
- Scan TCP ports on a specified IP address or hostname
- Custom port range (1–65535)
- Real-time OPEN/CLOSED results
- Input validation and error handling
- Uses Python `socket` module

### Network Traffic Analyzer
- Real-time packet capture using Scapy
- Protocol filtering (TCP, UDP, ICMP)
- Port-based filtering (e.g., 80, 443, 22)
- Displays:
  - Timestamp
  - Source IP
  - Destination IP
  - Protocol
  - Source/Destination ports
- Graceful error handling for invalid filters

### Logging System
- Records scanning sessions
- Records monitoring sessions
- Stores logs in `Data/logs/`

---

## 📂 Project Structure

```
LocalSecurityToolPortable/
│
├── LocalSecurityTool.bat
├── LocalSecurityTool.sh
├── LocalSecurityTool.desktop
│
├── App/
│   ├── suite_main.py
│   ├── PortScanner/
│   ├── NetworkTrafficAnalyzer/
│
├── Data/
│   ├── logs/
│   ├── settings/
│
└── README.md
```

---

## 💻 Requirements

- Python 3.8+
- Scapy (required for traffic monitoring)
- Windows, Linux, or macOS
- Administrator/root privileges may be required for packet capture

Install Scapy if needed:

```bash
pip install scapy
```

---

## 🚀 How to Run

### Windows

Double-click:

```
LocalSecurityTool.bat
```

For packet capture, run as **Administrator**.

---

### Linux

```bash
chmod +x LocalSecurityTool.sh
./LocalSecurityTool.sh
```

If packet capture fails:

```bash
sudo ./LocalSecurityTool.sh
```

---

### macOS

```bash
./LocalSecurityTool.sh
```

---

## 🖥 Application Menu

Upon launch:

```
LOCAL SECURITY TOOL
1. Port Scanner
2. Traffic Analyzer
3. View Logs
4. Exit
```

Users select the desired module from the integrated menu.

---

## 🎓 Educational Purpose

This project demonstrates:

- Modular program design  
- Socket-based port scanning  
- Real-time packet analysis using Scapy  
- Protocol and port filtering  
- Error handling and validation  
- Logging and audit trail mechanisms  
- Integration of multiple security utilities  

Developed for academic purposes under **MO-IT142 Security Script Programming**.

---

## 📜 License

Educational use only.

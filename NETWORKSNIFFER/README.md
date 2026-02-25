# 🛡️ NetProbe - Advanced Python Network Sniffer

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/platform-Linux-orange?logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/status-active-brightgreen" />
</p>

A feature-rich, pure-Python network packet sniffer built from raw sockets. No third-party dependencies required. Designed for authorized penetration testing, network diagnostics, and cybersecurity education on Linux systems (tested on Parrot OS and Kali Linux).

---

## ⚠️ LEGAL DISCLAIMER & WARNING

> **This tool is provided for AUTHORIZED SECURITY TESTING and EDUCATIONAL PURPOSES ONLY.**

**By downloading, installing, or using this software, you acknowledge and agree to the following:**

1. **Authorization Required** — You must have explicit, written authorization from the network owner before capturing any traffic. Unauthorized interception of network communications is a **criminal offense** in most jurisdictions worldwide.

2. **Applicable Laws** — Unauthorized network sniffing may violate:
   - 🇺🇸 **USA**: Computer Fraud and Abuse Act (CFAA), Electronic Communications Privacy Act (ECPA), Wiretap Act
   - 🇬🇧 **UK**: Computer Misuse Act 1990, Regulation of Investigatory Powers Act 2000
   - 🇪🇺 **EU**: General Data Protection Regulation (GDPR), national cybercrime laws
   - 🇿🇦 **South Africa**: Cybercrimes Act 19 of 2020, Electronic Communications and Transactions Act
   - **Other**: Virtually every country has laws prohibiting unauthorized interception of electronic communications

3. **Penalties** — Violations can result in **criminal prosecution**, **imprisonment**, **fines**, and **civil liability**.

4. **Your Responsibility** — The author(s) of this tool accept **NO liability** for misuse. You are solely responsible for ensuring your use complies with all applicable local, state, national, and international laws.

5. **Ethical Use** — This tool should only be used for:
   - Penetration testing with written scope agreements
   - Network troubleshooting on your own infrastructure
   - Cybersecurity research in controlled lab environments
   - Educational purposes in authorized training settings

> **If you are unsure whether your intended use is legal — DO NOT use this tool. Consult a legal professional.**

---

## ✨ Features

- **Pure Python** — Zero external dependencies, uses only the standard library
- **Deep Packet Parsing** — Ethernet, IPv4, TCP (with options), UDP, ICMP, ARP, DNS
- **Multi-Verbosity Display** — Compact one-liner, normal detail, or full hex dump modes
- **Smart Filtering** — Filter by protocol, source/destination IP, port, or any combination
- **Live Statistics** — Protocol breakdown, top talkers, port activity, traffic rates
- **Anomaly Detection** — Flags NULL scans, XMAS scans, ARP storms, SYN floods
- **Export Formats** — Save captures to JSON, CSV, or plain text
- **Promiscuous Mode** — Capture traffic not addressed to your NIC
- **Service Resolution** — Identifies 80+ common services by port number
- **HTTP Inspection** — Detects and displays HTTP request methods and URIs
- **DNS Decoding** — Parses and shows DNS query names and response types
- **TCP Option Parsing** — MSS, Window Scale, SACK, Timestamps
- **Color-Coded Output** — Protocol-specific coloring for quick visual identification
- **Graceful Shutdown** — Ctrl+C triggers clean stop with full session summary

---

## 📋 Requirements

| Requirement    | Details                         |
|----------------|---------------------------------|
| **OS**         | Linux (Parrot OS, Kali, Ubuntu) |
| **Python**     | 3.8+                           |
| **Privileges** | Root / sudo                     |
| **Dependencies** | None (stdlib only)            |

> **Note:** This tool uses `AF_PACKET` raw sockets which are only available on Linux.

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Michael-Chileshe/cybersec-tools.git
cd cybersec-tools/network-sniffer

# Make executable
chmod +x sniffer.py

# Run (requires root)
sudo python3 sniffer.py

# Basic capture on specific interface
sudo python3 sniffer.py -i eth0

# Capture with filters
sudo python3 sniffer.py -p TCP --port 80 -v
```

---

## 📖 Usage Examples

```bash
# Capture all traffic on all interfaces
sudo python3 sniffer.py

# Capture on a specific interface
sudo python3 sniffer.py -i eth0
sudo python3 sniffer.py -i wlan0

# Filter by protocol
sudo python3 sniffer.py -p TCP
sudo python3 sniffer.py -p UDP
sudo python3 sniffer.py -p ICMP
sudo python3 sniffer.py -p ARP

# Filter by IP address
sudo python3 sniffer.py --ip 192.168.1.1         # Either source or dest
sudo python3 sniffer.py --src-ip 10.0.0.5         # Source only
sudo python3 sniffer.py --dst-ip 8.8.8.8          # Destination only

# Filter by port
sudo python3 sniffer.py --port 443                # Either direction
sudo python3 sniffer.py --dst-port 22              # SSH connections

# Combine filters
sudo python3 sniffer.py -p TCP --ip 192.168.1.100 --port 80

# Verbosity levels
sudo python3 sniffer.py -v                         # Normal (multi-line)
sudo python3 sniffer.py -vv                        # Full dump with hex + payload

# Limit capture count
sudo python3 sniffer.py -c 50                      # Stop after 50 packets

# Export captures
sudo python3 sniffer.py -o capture.json            # JSON export
sudo python3 sniffer.py -o capture.csv             # CSV export
sudo python3 sniffer.py -o capture.txt             # Text log

# Promiscuous mode
sudo python3 sniffer.py -i eth0 --promisc

# Quiet mode (summary only)
sudo python3 sniffer.py -q -c 1000 -o results.json

# Real-world scenario: Monitor DNS traffic
sudo python3 sniffer.py -p UDP --port 53 -v -o dns_log.json

# Real-world scenario: Watch for SSH connections
sudo python3 sniffer.py -p TCP --port 22 -vv
```

---

## 📁 Project Structure

```
network-sniffer/
├── sniffer.py              # Main sniffer tool
├── README.md               # This file (overview + legal warning)
├── CODE_EXPLANATION.md     # Detailed code walkthrough
└── USER_MANUAL.md          # Full usage manual
```

---

## 🤝 Contributing

Contributions are welcome! Please ensure any pull requests:
1. Follow ethical guidelines
2. Include appropriate documentation
3. Do not add capabilities designed for malicious use

---

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](../LICENSE) file for details.

---

## 🔗 Related Tools

This is part of the **cybersec-tools** repository. More tools coming soon.

---

<p align="center">
  <b>Built for defenders. Use responsibly. 🛡️</b>
</p>

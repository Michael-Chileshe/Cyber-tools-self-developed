# 📚 NetProbe — Code Explanation

This document provides a thorough, section-by-section walkthrough of how `sniffer.py` works internally. It is intended for learners, contributors, and anyone wanting to understand raw socket packet sniffing in Python at a deeper level.

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [How Raw Sockets Work](#2-how-raw-sockets-work)
3. [Class Breakdown](#3-class-breakdown)
4. [Packet Parsing Pipeline](#4-packet-parsing-pipeline)
5. [Protocol Dissection Details](#5-protocol-dissection-details)
6. [Filtering System](#6-filtering-system)
7. [Statistics and Anomaly Detection](#7-statistics-and-anomaly-detection)
8. [Export System](#8-export-system)
9. [Display System](#9-display-system)
10. [Key Concepts for Beginners](#10-key-concepts-for-beginners)

---

## 1. High-Level Architecture

The sniffer follows a pipeline model:

```
Raw Socket → Ethernet Frame → IP Header → Transport Header → Application Data
                  ↓                ↓              ↓                 ↓
              Parse MAC       Parse IPs      Parse Ports       Parse DNS/HTTP
                  ↓                ↓              ↓                 ↓
                  └────────────────┴──────────────┴─────────────────┘
                                          ↓
                                    Apply Filters
                                          ↓
                                  ┌───────┴───────┐
                                  ↓               ↓
                            Display to        Export to
                             Terminal           File
                                  ↓
                            Update Stats
```

The entire tool is built around six core classes: `PacketParser` (parsing), `PacketDisplay` (output formatting), `PacketFilter` (filtering), `PacketStats` (statistics and anomaly detection), `PacketExporter` (file output), and `NetProbe` (the orchestrating engine).

---

## 2. How Raw Sockets Work

### What is a Raw Socket?

A regular socket (like what a web browser uses) only gives you application-level data — the HTTP response body, for instance. A **raw socket** gives you the entire packet including all headers, starting from the Ethernet frame.

### The Socket Call

```python
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
```

Breaking this down:

- `socket.AF_PACKET` — This tells the kernel we want to operate at the link layer (Layer 2). This is Linux-specific and gives us access to raw Ethernet frames.

- `socket.SOCK_RAW` — We want raw, unprocessed packets. The kernel will not strip any headers.

- `socket.ntohs(3)` — The protocol number `3` corresponds to `ETH_P_ALL`, which means "capture every protocol". `ntohs()` converts from host byte order to network byte order (big-endian), which is required for the protocol field.

### Why Root is Required

Raw sockets bypass the normal networking stack and can see all traffic on the wire. This is a privileged operation because it could be used to spy on other users' traffic. The Linux kernel enforces this with `CAP_NET_RAW` capability, which is typically only available to root.

### Promiscuous Mode

Normally, a network interface card (NIC) only accepts packets addressed to its own MAC address (plus broadcast/multicast). **Promiscuous mode** tells the NIC to capture ALL packets on the wire, regardless of destination MAC. This is done via the `ioctl` system call:

```python
# Get current interface flags
flags = struct.unpack('16xH', fcntl.ioctl(sock, SIOCGIFFLAGS, ifreq)[:18])[0]
# Set the IFF_PROMISC bit
flags |= IFF_PROMISC
# Apply the updated flags
fcntl.ioctl(sock, SIOCSIFFLAGS, struct.pack('16sH', interface_name, flags))
```

On a switched network, promiscuous mode only captures traffic that reaches your port. On a hub or with ARP spoofing, it captures everything.

---

## 3. Class Breakdown

### `Colors`
A simple container for ANSI escape codes used for terminal coloring. Protocols get distinct colors for visual parsing: green for TCP, blue for UDP, magenta for ARP/ICMP, cyan for headers.

### `PacketParser` (Static Methods)
This is the core parsing engine. Every method is `@staticmethod` because parsing is stateless — it takes raw bytes in and returns a structured dictionary out. Methods include:

- `parse_ethernet()` — Reads the 14-byte Ethernet header
- `parse_ipv4()` — Reads the 20+ byte IPv4 header
- `parse_tcp()` — Reads the 20+ byte TCP header including options
- `parse_udp()` — Reads the 8-byte UDP header
- `parse_icmp()` — Reads the ICMP header with type-specific data
- `parse_arp()` — Reads the 28-byte ARP packet
- `parse_dns()` — Reads DNS header and extracts query name

### `PacketDisplay`
Handles three verbosity levels of output formatting. Level 0 is a single line per packet, Level 1 is multi-line with key fields, and Level 2 adds hex dumps and payload previews.

### `PacketFilter`
A configurable filter that checks parsed packet fields against user-specified criteria. Supports protocol, source/destination IP, source/destination port, and host-based filtering. All criteria are AND-combined.

### `PacketStats`
Tracks running statistics: packet counts by protocol, top source/destination IPs, port frequency, protocol-specific counters (DNS, HTTP, HTTPS, ARP), and suspicious activity detection.

### `PacketExporter`
Serializes captured packet metadata to JSON, CSV, or plain text files. Non-serializable fields (raw bytes) are converted to hex strings.

### `NetProbe`
The orchestrating engine that ties everything together. It creates the raw socket, runs the main capture loop, calls the parser, applies filters, updates stats, triggers display output, and feeds the exporter.

---

## 4. Packet Parsing Pipeline

When a packet arrives, it goes through a layered parsing process that mirrors the OSI model:

### Step 1: Ethernet Frame (Layer 2)

Every packet on an Ethernet network starts with a 14-byte header:

```
[Dest MAC: 6 bytes][Source MAC: 6 bytes][EtherType: 2 bytes][Payload...]
```

```python
dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
```

The `!` means network byte order (big-endian). `6s` reads 6 raw bytes (MAC address), and `H` reads an unsigned short (EtherType). The EtherType tells us what's in the payload: `0x0800` for IPv4, `0x0806` for ARP, `0x86DD` for IPv6.

### Step 2: Network Layer (Layer 3)

**IPv4 Header** (20-60 bytes):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|    Fragment Offset      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The first byte contains both version (always 4) and IHL (Internet Header Length) packed into 4 bits each. IHL tells us the header size in 32-bit words, so we multiply by 4 to get bytes. This is important because IP options can extend the header beyond the standard 20 bytes.

**ARP Packet** (28 bytes for IPv4 over Ethernet):
ARP maps IP addresses to MAC addresses. The opcode field indicates REQUEST (1) or REPLY (2). The sniffer extracts both the sender and target hardware/protocol addresses.

### Step 3: Transport Layer (Layer 4)

**TCP Header** (20-60 bytes):
The TCP parser extracts ports, sequence/acknowledgment numbers, flags, window size, and TCP options. Flags are extracted via bitmasking:

```python
flags_raw = offset_flags & 0x1FF  # Lower 9 bits contain flags
for bit, name in TCP_FLAGS.items():
    if flags_raw & bit:
        flags.append(name)
```

TCP options (MSS, Window Scale, SACK, Timestamps) live between byte 20 and the data offset boundary. They're parsed with a TLV (Type-Length-Value) loop.

**UDP Header** (8 bytes): Much simpler — just source port, destination port, length, and checksum.

**ICMP Header** (4+ bytes): Contains type, code, and checksum, with type-specific data following (like identifier and sequence for echo request/reply).

### Step 4: Application Layer (Layer 7)

**DNS Parsing**: When a UDP packet has port 53, the payload is parsed as DNS. The parser extracts the transaction ID, flags (query vs response), and the query name using the DNS label encoding format (length-prefixed segments ending with a null byte).

**HTTP Detection**: TCP payloads starting with `GET `, `POST`, `HTTP`, `PUT `, or `HEAD` trigger HTTP line extraction from the first CRLF-delimited line.

---

## 5. Protocol Dissection Details

### `struct.unpack` Format Strings

The `struct` module is the backbone of all parsing. Key format characters:

| Format | Type | Size | Description |
|--------|------|------|-------------|
| `!` | — | — | Network byte order (big-endian) |
| `B` | unsigned char | 1 byte | Single byte (e.g., TTL, protocol) |
| `H` | unsigned short | 2 bytes | Ports, lengths, flags |
| `I` | unsigned int | 4 bytes | Sequence numbers, IP addresses |
| `6s` | bytes | 6 bytes | MAC addresses |

### Byte Order

Network protocols use big-endian (most significant byte first). x86 CPUs use little-endian. The `!` prefix in `struct.unpack` handles the conversion, and `socket.ntohs()` / `socket.inet_ntoa()` handle it for specific fields.

### MAC Address Formatting

MAC addresses are 6 raw bytes that get formatted into the familiar colon-separated hex notation:

```python
':'.join(f'{b:02x}' for b in mac_bytes)
# b'\xaa\xbb\xcc\xdd\xee\xff' → 'aa:bb:cc:dd:ee:ff'
```

### IP Address Conversion

`socket.inet_ntoa()` converts 4 raw bytes to dotted-decimal notation:

```python
socket.inet_ntoa(data[12:16])  # b'\xc0\xa8\x01\x01' → '192.168.1.1'
```

### DNS Label Encoding

DNS names are encoded as length-prefixed labels. For example, `www.example.com` is stored as:
```
\x03www\x07example\x03com\x00
```
Each segment starts with a byte indicating its length, and the name ends with `\x00`. The parser reads these labels until it hits a null byte or a pointer (values > 63 indicate compression pointers in the DNS message).

---

## 6. Filtering System

The `PacketFilter` class implements AND-logic filtering. All specified criteria must match for a packet to pass through. The filter operates on the parsed `packet_info` dictionary after all headers have been dissected.

```python
def matches(self, packet_info):
    if self.protocol and packet_info.get("protocol", "").upper() != self.protocol:
        return False
    if self.src_ip and packet_info.get("src_ip") != self.src_ip:
        return False
    # ... more checks ...
    return True  # All checks passed
```

The `--ip` flag is special: it matches against EITHER source or destination IP, making it easy to see all traffic involving a specific host.

Filtering happens after parsing but before display and export, so filtered-out packets consume minimal resources.

---

## 7. Statistics and Anomaly Detection

### Running Statistics

`PacketStats` maintains `defaultdict` counters that update on every matching packet. After capture, it computes:

- Packets per second and bytes per second rates
- Protocol distribution with ASCII bar charts
- Top 5 source and destination IP addresses (heaviest talkers)
- Top 10 active ports with service name resolution
- Application protocol counters (DNS, HTTP, HTTPS, ARP)

### Anomaly / Suspicious Activity Detection

The `_detect_suspicious()` method performs lightweight heuristic analysis:

**NULL Scan Detection**: A TCP packet with zero flags set is abnormal and is a technique used by port scanners (like Nmap's `-sN` flag) to evade simple firewall rules. Normal TCP packets always have at least one flag set.

**XMAS Scan Detection**: A TCP packet with FIN, PSH, and URG all set simultaneously is called a "Christmas tree" packet (all lights on). This is another scanner evasion technique (`nmap -sX`) that exploits ambiguities in how different OSes handle invalid flag combinations.

**ARP Storm Detection**: An unusually high ratio of ARP packets to total traffic can indicate ARP spoofing, network misconfiguration, or a loop. The heuristic flags when ARP exceeds 100 packets in the first 500 captured.

**SYN Flood Indicator**: Tracks SYN-only packets (SYN flag without ACK). A high rate of these from varied sources targeting one destination is a signature of SYN flood DDoS attacks.

---

## 8. Export System

### JSON Export
The most complete format. Each packet becomes a JSON object with all parsed fields. Non-serializable bytes fields are converted to hex strings. This is ideal for post-processing with tools like `jq` or Python scripts.

### CSV Export
A tabular format with fixed columns: timestamp, protocol, source/destination IP, source/destination port, length, and a summary info string. This works well with spreadsheet applications and data analysis tools like pandas.

### Text Export
One line per packet with the essential information. Lightweight and easy to grep through.

The export format is auto-detected from the file extension, so `-o capture.json` produces JSON while `-o capture.csv` produces CSV.

---

## 9. Display System

### Verbosity Level 0 (Default — Compact)

One line per packet with color-coded protocol, addresses, ports, service names, and TCP flags:

```
    1 14:23:01.456 TCP   192.168.1.5:54321 → 93.184.216.34:443 (HTTPS) [SYN]
```

### Verbosity Level 1 (`-v` — Normal)

Multi-line display with separated layers:

```
  ────────────────────────────────────────────────────
  Packet #1 | 14:23:01.456 | IPv4
  MAC: aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66
  IP:  192.168.1.5 → 93.184.216.34 | TTL:64 | Proto:TCP | Len:60
  TCP: 54321 → 443 | Flags:[SYN] | Seq:123456 | Ack:0 | Win:65535
       Options: MSS, Window Scale, SACK Permitted, Timestamps
```

### Verbosity Level 2 (`-vv` — Full Dump)

Everything from Level 1 plus ASCII payload preview and hex dump:

```
  Payload Preview:
    GET / HTTP/1.1
    Host: example.com
  Hex Dump:
    0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
```

---

## 10. Key Concepts for Beginners

### The OSI Model in Practice

This sniffer works through Layers 2-7 of the OSI model. When you see a packet, you're looking at nested envelopes: the Ethernet frame contains an IP packet, which contains a TCP segment, which contains application data.

### Why `struct.unpack`?

Network data arrives as raw bytes. Protocols define exactly which bits mean what. `struct.unpack` lets us read those bytes in the exact format the protocol specifies. The `!` prefix ensures we handle the big-endian byte order that all network protocols use.

### What "Sniffing" Actually Does

When we call `sock.recvfrom(65535)`, the kernel hands us a copy of a packet it received. The original packet continues to its destination normally. Sniffing is passive observation — it does not modify, block, or inject traffic (though more advanced tools can).

### Why Only Linux?

`AF_PACKET` is a Linux-specific socket family. Windows uses `WinPcap` or `Npcap` (typically via the Scapy or pcap libraries), and macOS uses `BPF` (Berkeley Packet Filter). Writing a cross-platform sniffer from raw sockets would require platform-specific code for each OS, or using a wrapper library like libpcap.

### Security Implications

Every piece of unencrypted data (HTTP, DNS, FTP, Telnet, etc.) is visible to anyone running a sniffer on the same network segment. This is why encryption (HTTPS, SSH, WireGuard, etc.) is critical. This tool helps demonstrate that point.

---

*This document is part of the NetProbe project. See [README.md](README.md) for setup and legal information.*

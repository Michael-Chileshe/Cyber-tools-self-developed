#!/usr/bin/env python3
"""
NetProbe - Advanced Python Network Sniffer
Author: Michael Chileshe
License: MIT
Repository: https://github.com/Michael-Chileshe/cybersec-tools

WARNING: This tool is intended for authorized security testing and educational
purposes ONLY. Unauthorized network sniffing is illegal in most jurisdictions.
Always obtain proper written authorization before using this tool on any network.
"""

import socket
import struct
import sys
import os
import argparse
import signal
import time
import json
import csv
import textwrap
from datetime import datetime
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════
# ANSI Color Codes
# ═══════════════════════════════════════════════════════════════════

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"


# ═══════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════

BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
 ███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
 ██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{Colors.RESET}
{Colors.DIM}  Advanced Python Network Sniffer v1.0
  For authorized security testing only.{Colors.RESET}
"""


# ═══════════════════════════════════════════════════════════════════
# Protocol Constants
# ═══════════════════════════════════════════════════════════════════

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
}

IP_PROTOCOLS = {
    1:  "ICMP",
    2:  "IGMP",
    6:  "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132:"SCTP",
}

TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

ICMP_TYPES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request",
    9:  "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    30: "Traceroute",
}

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NETBIOS-NS", 138: "NETBIOS-DGM", 139: "NETBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
    515: "LPD", 587: "SMTP-SUB", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-UDP",
    1521: "ORACLE", 1723: "PPTP", 3306: "MYSQL", 3389: "RDP",
    5432: "POSTGRESQL", 5900: "VNC", 6379: "REDIS", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 8888: "HTTP-ALT2", 9200: "ELASTICSEARCH",
    27017: "MONGODB",
}


# ═══════════════════════════════════════════════════════════════════
# Packet Statistics Tracker
# ═══════════════════════════════════════════════════════════════════

class PacketStats:
    """Track and display packet capture statistics."""

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_count = defaultdict(int)
        self.src_ip_count = defaultdict(int)
        self.dst_ip_count = defaultdict(int)
        self.port_count = defaultdict(int)
        self.tcp_flags_count = defaultdict(int)
        self.start_time = time.time()
        self.arp_count = 0
        self.dns_count = 0
        self.http_count = 0
        self.https_count = 0
        self.suspicious_packets = []

    def update(self, packet_info):
        self.total_packets += 1
        self.total_bytes += packet_info.get("length", 0)
        proto = packet_info.get("protocol", "UNKNOWN")
        self.protocol_count[proto] += 1

        if "src_ip" in packet_info:
            self.src_ip_count[packet_info["src_ip"]] += 1
        if "dst_ip" in packet_info:
            self.dst_ip_count[packet_info["dst_ip"]] += 1
        if "src_port" in packet_info:
            self.port_count[packet_info["src_port"]] += 1
        if "dst_port" in packet_info:
            self.port_count[packet_info["dst_port"]] += 1

        # Track specific protocols
        if proto == "ARP":
            self.arp_count += 1
        if packet_info.get("dst_port") == 53 or packet_info.get("src_port") == 53:
            self.dns_count += 1
        if packet_info.get("dst_port") == 80 or packet_info.get("src_port") == 80:
            self.http_count += 1
        if packet_info.get("dst_port") == 443 or packet_info.get("src_port") == 443:
            self.https_count += 1

        # Detect suspicious patterns
        self._detect_suspicious(packet_info)

    def _detect_suspicious(self, pkt):
        """Basic anomaly/suspicious activity detection."""
        flags = pkt.get("tcp_flags", "")

        # NULL scan (no flags)
        if pkt.get("protocol") == "TCP" and flags == "":
            self.suspicious_packets.append(
                f"[NULL SCAN] {pkt.get('src_ip')}:{pkt.get('src_port')} -> "
                f"{pkt.get('dst_ip')}:{pkt.get('dst_port')}"
            )

        # XMAS scan (FIN+PSH+URG)
        if all(f in flags for f in ["FIN", "PSH", "URG"]):
            self.suspicious_packets.append(
                f"[XMAS SCAN] {pkt.get('src_ip')}:{pkt.get('src_port')} -> "
                f"{pkt.get('dst_ip')}:{pkt.get('dst_port')}"
            )

        # SYN flood indicator (SYN without ACK from same source, tracked externally)
        if flags == "SYN":
            self.tcp_flags_count["SYN-only"] += 1

        # ARP storm detection
        if self.arp_count > 100 and self.total_packets < 500:
            if len(self.suspicious_packets) == 0 or "ARP STORM" not in self.suspicious_packets[-1]:
                self.suspicious_packets.append(
                    f"[ARP STORM] High ARP traffic detected ({self.arp_count} packets)"
                )

    def display_summary(self):
        elapsed = time.time() - self.start_time
        pps = self.total_packets / elapsed if elapsed > 0 else 0
        bps = self.total_bytes / elapsed if elapsed > 0 else 0

        print(f"\n{'═' * 70}")
        print(f"{Colors.CYAN}{Colors.BOLD}  CAPTURE SUMMARY{Colors.RESET}")
        print(f"{'═' * 70}")
        print(f"  Duration       : {elapsed:.2f} seconds")
        print(f"  Total Packets  : {self.total_packets}")
        print(f"  Total Bytes    : {self._format_bytes(self.total_bytes)}")
        print(f"  Avg Rate       : {pps:.2f} packets/sec | {self._format_bytes(bps)}/sec")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}  Protocol Breakdown:{Colors.RESET}")
        for proto, count in sorted(self.protocol_count.items(), key=lambda x: x[1], reverse=True):
            pct = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"    {proto:<12} {count:>6} ({pct:5.1f}%) {Colors.GREEN}{bar}{Colors.RESET}")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}  Top 5 Source IPs:{Colors.RESET}")
        for ip, count in sorted(self.src_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {ip:<20} {count:>6} packets")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}  Top 5 Destination IPs:{Colors.RESET}")
        for ip, count in sorted(self.dst_ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {ip:<20} {count:>6} packets")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}  Top 10 Active Ports:{Colors.RESET}")
        for port, count in sorted(self.port_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            service = COMMON_PORTS.get(port, "")
            print(f"    {port:<8} {service:<16} {count:>6} packets")

        print(f"\n{Colors.YELLOW}{Colors.BOLD}  Application Protocols:{Colors.RESET}")
        print(f"    DNS   : {self.dns_count}")
        print(f"    HTTP  : {self.http_count}")
        print(f"    HTTPS : {self.https_count}")
        print(f"    ARP   : {self.arp_count}")

        if self.suspicious_packets:
            print(f"\n{Colors.RED}{Colors.BOLD}  ⚠  Suspicious Activity Detected:{Colors.RESET}")
            for s in self.suspicious_packets[-10:]:
                print(f"    {Colors.RED}{s}{Colors.RESET}")

        print(f"{'═' * 70}\n")

    @staticmethod
    def _format_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024:
                return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"


# ═══════════════════════════════════════════════════════════════════
# Packet Parser
# ═══════════════════════════════════════════════════════════════════

class PacketParser:
    """Parse raw packets at the Ethernet, IP, TCP, UDP, ICMP, and ARP layers."""

    @staticmethod
    def parse_ethernet(raw_data):
        """Parse Ethernet frame header (14 bytes)."""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        return {
            "dest_mac": PacketParser.format_mac(dest_mac),
            "src_mac": PacketParser.format_mac(src_mac),
            "ethertype": proto,
            "ethertype_name": ETHERTYPES.get(proto, f"0x{proto:04X}"),
            "payload": raw_data[14:]
        }

    @staticmethod
    def parse_ipv4(data):
        """Parse IPv4 header (20+ bytes)."""
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4

        if len(data) < ihl:
            return None

        tos, total_length, identification, flags_offset, ttl, protocol, checksum = struct.unpack(
            '! B H H H B B H', data[1:12]
        )

        flags = (flags_offset >> 13) & 0x7
        fragment_offset = flags_offset & 0x1FFF

        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        # Parse IP options if present
        options = data[20:ihl] if ihl > 20 else b''

        return {
            "version": version,
            "ihl": ihl,
            "tos": tos,
            "dscp": tos >> 2,
            "ecn": tos & 0x3,
            "total_length": total_length,
            "identification": identification,
            "flags": flags,
            "dont_fragment": bool(flags & 0x2),
            "more_fragments": bool(flags & 0x1),
            "fragment_offset": fragment_offset,
            "ttl": ttl,
            "protocol": protocol,
            "protocol_name": IP_PROTOCOLS.get(protocol, f"PROTO_{protocol}"),
            "checksum": checksum,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "options": options.hex() if options else "",
            "payload": data[ihl:]
        }

    @staticmethod
    def parse_tcp(data):
        """Parse TCP header (20+ bytes)."""
        if len(data) < 20:
            return None

        src_port, dst_port, seq, ack, offset_flags = struct.unpack('! H H I I H', data[:14])
        window, checksum, urgent = struct.unpack('! H H H', data[14:20])

        data_offset = (offset_flags >> 12) * 4
        flags_raw = offset_flags & 0x1FF

        flags = []
        for bit, name in TCP_FLAGS.items():
            if flags_raw & bit:
                flags.append(name)

        # Parse TCP options
        options = []
        if data_offset > 20:
            opts_data = data[20:data_offset]
            options = PacketParser._parse_tcp_options(opts_data)

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "src_service": COMMON_PORTS.get(src_port, ""),
            "dst_service": COMMON_PORTS.get(dst_port, ""),
            "sequence": seq,
            "acknowledgment": ack,
            "data_offset": data_offset,
            "flags": flags,
            "flags_raw": flags_raw,
            "window": window,
            "checksum": checksum,
            "urgent_pointer": urgent,
            "options": options,
            "payload": data[data_offset:]
        }

    @staticmethod
    def _parse_tcp_options(data):
        """Parse TCP options from header."""
        options = []
        i = 0
        while i < len(data):
            kind = data[i]
            if kind == 0:  # End of options
                break
            elif kind == 1:  # NOP
                options.append({"kind": "NOP"})
                i += 1
            else:
                if i + 1 >= len(data):
                    break
                length = data[i + 1]
                if length < 2 or i + length > len(data):
                    break
                opt_data = data[i + 2:i + length]
                opt_name = {2: "MSS", 3: "Window Scale", 4: "SACK Permitted",
                            5: "SACK", 8: "Timestamps"}.get(kind, f"Option_{kind}")

                opt_info = {"kind": opt_name}
                if kind == 2 and len(opt_data) == 2:
                    opt_info["mss"] = struct.unpack('!H', opt_data)[0]
                elif kind == 3 and len(opt_data) == 1:
                    opt_info["shift"] = opt_data[0]
                elif kind == 8 and len(opt_data) == 8:
                    tsval, tsecr = struct.unpack('!II', opt_data)
                    opt_info["tsval"] = tsval
                    opt_info["tsecr"] = tsecr

                options.append(opt_info)
                i += length
        return options

    @staticmethod
    def parse_udp(data):
        """Parse UDP header (8 bytes)."""
        if len(data) < 8:
            return None

        src_port, dst_port, length, checksum = struct.unpack('! H H H H', data[:8])
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "src_service": COMMON_PORTS.get(src_port, ""),
            "dst_service": COMMON_PORTS.get(dst_port, ""),
            "length": length,
            "checksum": checksum,
            "payload": data[8:]
        }

    @staticmethod
    def parse_icmp(data):
        """Parse ICMP header."""
        if len(data) < 4:
            return None

        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

        result = {
            "type": icmp_type,
            "type_name": ICMP_TYPES.get(icmp_type, f"Type_{icmp_type}"),
            "code": code,
            "checksum": checksum,
            "payload": data[4:]
        }

        # Parse type-specific data
        if icmp_type in (0, 8) and len(data) >= 8:  # Echo
            result["identifier"], result["sequence"] = struct.unpack('! H H', data[4:8])
        elif icmp_type == 3 and len(data) >= 8:  # Destination Unreachable
            result["next_hop_mtu"] = struct.unpack('! H', data[6:8])[0]
        elif icmp_type == 11 and len(data) >= 8:  # Time Exceeded
            pass  # Contains original datagram header

        return result

    @staticmethod
    def parse_arp(data):
        """Parse ARP packet."""
        if len(data) < 28:
            return None

        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack('! H H B B H', data[:8])

        sender_mac = PacketParser.format_mac(data[8:14])
        sender_ip = socket.inet_ntoa(data[14:18])
        target_mac = PacketParser.format_mac(data[18:24])
        target_ip = socket.inet_ntoa(data[24:28])

        return {
            "hw_type": hw_type,
            "proto_type": proto_type,
            "hw_size": hw_size,
            "proto_size": proto_size,
            "opcode": opcode,
            "opcode_name": "REQUEST" if opcode == 1 else "REPLY" if opcode == 2 else f"OP_{opcode}",
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip,
        }

    @staticmethod
    def parse_dns(data):
        """Parse DNS header (basic)."""
        if len(data) < 12:
            return None

        tx_id, flags, questions, answers, authority, additional = struct.unpack(
            '! H H H H H H', data[:12]
        )

        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        rcode = flags & 0xF

        result = {
            "transaction_id": tx_id,
            "is_response": bool(qr),
            "opcode": opcode,
            "rcode": rcode,
            "questions": questions,
            "answers": answers,
            "authority": authority,
            "additional": additional,
        }

        # Try to parse the query name
        try:
            name_parts = []
            offset = 12
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if length > 63:  # Pointer
                    break
                offset += 1
                name_parts.append(data[offset:offset + length].decode('ascii', errors='replace'))
                offset += length
            result["query_name"] = ".".join(name_parts) if name_parts else ""
        except (IndexError, UnicodeDecodeError):
            result["query_name"] = ""

        return result

    @staticmethod
    def format_mac(mac_bytes):
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    @staticmethod
    def format_hex_dump(data, length=64):
        """Create a hex dump of raw data."""
        lines = []
        for i in range(0, min(len(data), length), 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"    {i:04x}  {hex_part:<48}  {ascii_part}")
        if len(data) > length:
            lines.append(f"    ... ({len(data) - length} more bytes)")
        return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# Packet Display Formatter
# ═══════════════════════════════════════════════════════════════════

class PacketDisplay:
    """Format and display parsed packet information."""

    @staticmethod
    def display_packet(packet_num, timestamp, eth, ip=None, transport=None,
                       app=None, raw_data=b'', verbose=0):
        """Display a single packet with configurable verbosity."""

        ts = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]

        if verbose == 0:
            PacketDisplay._display_compact(packet_num, ts, eth, ip, transport, app)
        elif verbose == 1:
            PacketDisplay._display_normal(packet_num, ts, eth, ip, transport, app)
        else:
            PacketDisplay._display_verbose(packet_num, ts, eth, ip, transport, app, raw_data)

    @staticmethod
    def _display_compact(num, ts, eth, ip, transport, app):
        """One-line per packet display."""
        if ip and transport:
            proto = ip.get("protocol_name", "?")
            src = ip["src_ip"]
            dst = ip["dst_ip"]
            sport = transport.get("src_port", "")
            dport = transport.get("dst_port", "")
            service = transport.get("dst_service", "") or transport.get("src_service", "")
            flags = ",".join(transport.get("flags", [])) if "flags" in transport else ""

            color = Colors.GREEN if proto == "TCP" else Colors.BLUE if proto == "UDP" else Colors.YELLOW

            extra = ""
            if flags:
                extra = f" [{flags}]"
            if app and "query_name" in app:
                extra += f" DNS:{app['query_name']}"
            if service:
                extra = f" ({service}){extra}"

            print(f"  {Colors.DIM}{num:>5} {ts}{Colors.RESET} {color}{proto:<5}{Colors.RESET} "
                  f"{src}:{sport} → {dst}:{dport}{extra}")

        elif eth.get("ethertype") == 0x0806 and app:  # ARP
            print(f"  {Colors.DIM}{num:>5} {ts}{Colors.RESET} {Colors.MAGENTA}ARP  {Colors.RESET} "
                  f"{app['sender_ip']} ({app['sender_mac']}) → {app['target_ip']} "
                  f"[{app['opcode_name']}]")
        else:
            print(f"  {Colors.DIM}{num:>5} {ts}{Colors.RESET} {Colors.DIM}{eth['ethertype_name']:<5}{Colors.RESET} "
                  f"{eth['src_mac']} → {eth['dest_mac']}")

    @staticmethod
    def _display_normal(num, ts, eth, ip, transport, app):
        """Multi-line packet display with key details."""
        print(f"\n  {Colors.CYAN}{'─' * 64}{Colors.RESET}")
        print(f"  {Colors.BOLD}Packet #{num}{Colors.RESET} | {ts} | {eth['ethertype_name']}")
        print(f"  {Colors.DIM}MAC: {eth['src_mac']} → {eth['dest_mac']}{Colors.RESET}")

        if ip:
            print(f"  {Colors.GREEN}IP:  {ip['src_ip']} → {ip['dst_ip']} "
                  f"| TTL:{ip['ttl']} | Proto:{ip['protocol_name']} "
                  f"| Len:{ip['total_length']}{Colors.RESET}")

            if ip.get("dont_fragment"):
                print(f"       DF flag set | ID: 0x{ip['identification']:04x}")

        if transport:
            if "flags" in transport:  # TCP
                flags_str = ",".join(transport["flags"]) or "NONE"
                print(f"  {Colors.YELLOW}TCP: {transport['src_port']} → {transport['dst_port']} "
                      f"| Flags:[{flags_str}] | Seq:{transport['sequence']} "
                      f"| Ack:{transport['acknowledgment']} | Win:{transport['window']}{Colors.RESET}")
                if transport.get("options"):
                    opts = [o["kind"] for o in transport["options"]]
                    print(f"       Options: {', '.join(opts)}")
            elif "length" in transport and "src_port" in transport:  # UDP
                print(f"  {Colors.BLUE}UDP: {transport['src_port']} → {transport['dst_port']} "
                      f"| Len:{transport['length']}{Colors.RESET}")
            elif "type" in transport and "type_name" in transport:  # ICMP
                print(f"  {Colors.MAGENTA}ICMP: Type:{transport['type']} ({transport['type_name']}) "
                      f"| Code:{transport['code']}{Colors.RESET}")
                if "identifier" in transport:
                    print(f"        ID:{transport['identifier']} | Seq:{transport['sequence']}")

        if app:
            if "query_name" in app:
                direction = "Response" if app["is_response"] else "Query"
                print(f"  {Colors.WHITE}DNS {direction}: {app['query_name']} "
                      f"| TxID:0x{app['transaction_id']:04x}{Colors.RESET}")
            elif "opcode_name" in app:
                print(f"  {Colors.MAGENTA}ARP {app['opcode_name']}: "
                      f"{app['sender_ip']} ({app['sender_mac']}) → "
                      f"{app['target_ip']} ({app['target_mac']}){Colors.RESET}")

    @staticmethod
    def _display_verbose(num, ts, eth, ip, transport, app, raw_data):
        """Full packet dump with hex."""
        PacketDisplay._display_normal(num, ts, eth, ip, transport, app)

        payload = b''
        if transport and "payload" in transport:
            payload = transport["payload"]
        elif ip and "payload" in ip:
            payload = ip["payload"]

        if payload:
            # Try to show ASCII content
            try:
                text = payload[:256].decode('utf-8', errors='replace')
                printable = ''.join(c if c.isprintable() or c in '\r\n\t' else '.' for c in text)
                if any(c.isalpha() for c in printable[:50]):
                    print(f"  {Colors.DIM}Payload Preview:{Colors.RESET}")
                    for line in printable.split('\n')[:5]:
                        if line.strip():
                            print(f"    {Colors.DIM}{line.strip()[:80]}{Colors.RESET}")
            except Exception:
                pass

            print(f"  {Colors.DIM}Hex Dump:{Colors.RESET}")
            print(PacketParser.format_hex_dump(payload))


# ═══════════════════════════════════════════════════════════════════
# BPF-like Packet Filter
# ═══════════════════════════════════════════════════════════════════

class PacketFilter:
    """Filter packets based on user-defined criteria."""

    def __init__(self, protocol=None, src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None, port=None, ip=None):
        self.protocol = protocol.upper() if protocol else None
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = int(src_port) if src_port else None
        self.dst_port = int(dst_port) if dst_port else None
        self.port = int(port) if port else None
        self.ip = ip

    def matches(self, packet_info):
        """Check if a packet matches the filter criteria."""
        if self.protocol:
            if packet_info.get("protocol", "").upper() != self.protocol:
                return False

        if self.src_ip:
            if packet_info.get("src_ip") != self.src_ip:
                return False

        if self.dst_ip:
            if packet_info.get("dst_ip") != self.dst_ip:
                return False

        if self.ip:
            if packet_info.get("src_ip") != self.ip and packet_info.get("dst_ip") != self.ip:
                return False

        if self.src_port:
            if packet_info.get("src_port") != self.src_port:
                return False

        if self.dst_port:
            if packet_info.get("dst_port") != self.dst_port:
                return False

        if self.port:
            if (packet_info.get("src_port") != self.port and
                    packet_info.get("dst_port") != self.port):
                return False

        return True


# ═══════════════════════════════════════════════════════════════════
# Export Handlers
# ═══════════════════════════════════════════════════════════════════

class PacketExporter:
    """Export captured packets to various formats."""

    def __init__(self, filepath, fmt="json"):
        self.filepath = filepath
        self.fmt = fmt
        self.packets = []

    def add_packet(self, packet_info):
        """Add a packet record for export."""
        # Clean up non-serializable fields
        clean = {}
        for k, v in packet_info.items():
            if isinstance(v, bytes):
                clean[k] = v.hex()
            else:
                clean[k] = v
        self.packets.append(clean)

    def save(self):
        """Write all captured packets to file."""
        if self.fmt == "json":
            self._save_json()
        elif self.fmt == "csv":
            self._save_csv()
        elif self.fmt == "txt":
            self._save_txt()

    def _save_json(self):
        with open(self.filepath, 'w') as f:
            json.dump(self.packets, f, indent=2, default=str)

    def _save_csv(self):
        if not self.packets:
            return
        fieldnames = ["timestamp", "protocol", "src_ip", "dst_ip",
                      "src_port", "dst_port", "length", "info"]
        with open(self.filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(self.packets)

    def _save_txt(self):
        with open(self.filepath, 'w') as f:
            for pkt in self.packets:
                line = (f"{pkt.get('timestamp', '')} | {pkt.get('protocol', '')} | "
                        f"{pkt.get('src_ip', '')}:{pkt.get('src_port', '')} -> "
                        f"{pkt.get('dst_ip', '')}:{pkt.get('dst_port', '')} | "
                        f"{pkt.get('info', '')}")
                f.write(line + '\n')


# ═══════════════════════════════════════════════════════════════════
# Main Sniffer Engine
# ═══════════════════════════════════════════════════════════════════

class NetProbe:
    """Core network sniffer engine."""

    def __init__(self, args):
        self.args = args
        self.stats = PacketStats()
        self.packet_count = 0
        self.running = True
        self.exporter = None
        self.packet_filter = None

        # Setup filter
        if any([args.protocol, args.src_ip, args.dst_ip, args.src_port,
                args.dst_port, args.port, args.ip]):
            self.packet_filter = PacketFilter(
                protocol=args.protocol, src_ip=args.src_ip, dst_ip=args.dst_ip,
                src_port=args.src_port, dst_port=args.dst_port,
                port=args.port, ip=args.ip
            )

        # Setup exporter
        if args.output:
            fmt = "json"
            if args.output.endswith('.csv'):
                fmt = "csv"
            elif args.output.endswith('.txt'):
                fmt = "txt"
            self.exporter = PacketExporter(args.output, fmt)

        # Signal handler
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        self.running = False
        print(f"\n\n{Colors.YELLOW}[*] Capture stopped by user.{Colors.RESET}")

    def start(self):
        """Start the packet capture."""
        if os.geteuid() != 0:
            print(f"{Colors.RED}[!] Error: Root privileges required. Run with sudo.{Colors.RESET}")
            sys.exit(1)

        if not self.args.quiet:
            print(BANNER)

        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            if self.args.interface:
                sock.bind((self.args.interface, 0))
                iface = self.args.interface
            else:
                iface = "all interfaces"

            if self.args.promisc and self.args.interface:
                self._set_promisc(self.args.interface, True)

        except PermissionError:
            print(f"{Colors.RED}[!] Permission denied. Run as root.{Colors.RESET}")
            sys.exit(1)
        except OSError as e:
            print(f"{Colors.RED}[!] Socket error: {e}{Colors.RESET}")
            sys.exit(1)

        # Print capture info
        print(f"  {Colors.GREEN}[+] Listening on: {iface}{Colors.RESET}")
        if self.packet_filter:
            filters = []
            if self.args.protocol: filters.append(f"proto={self.args.protocol}")
            if self.args.src_ip: filters.append(f"src={self.args.src_ip}")
            if self.args.dst_ip: filters.append(f"dst={self.args.dst_ip}")
            if self.args.port: filters.append(f"port={self.args.port}")
            if self.args.ip: filters.append(f"host={self.args.ip}")
            print(f"  {Colors.GREEN}[+] Filter: {', '.join(filters)}{Colors.RESET}")
        if self.args.count:
            print(f"  {Colors.GREEN}[+] Capture limit: {self.args.count} packets{Colors.RESET}")
        if self.args.output:
            print(f"  {Colors.GREEN}[+] Saving to: {self.args.output}{Colors.RESET}")

        print(f"  {Colors.DIM}Press Ctrl+C to stop capture{Colors.RESET}\n")

        # ═══ Main Capture Loop ═══
        try:
            while self.running:
                if self.args.count and self.packet_count >= self.args.count:
                    break

                raw_data, addr = sock.recvfrom(65535)
                timestamp = time.time()

                self._process_packet(raw_data, timestamp)

        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        finally:
            sock.close()
            if self.args.promisc and self.args.interface:
                self._set_promisc(self.args.interface, False)

            # Save exports
            if self.exporter:
                self.exporter.save()
                print(f"\n  {Colors.GREEN}[+] Packets saved to: {self.args.output}{Colors.RESET}")

            # Show summary
            if not self.args.quiet:
                self.stats.display_summary()

    def _process_packet(self, raw_data, timestamp):
        """Parse and process a single raw packet."""

        eth = PacketParser.parse_ethernet(raw_data)
        ip = None
        transport = None
        app = None
        packet_info = {
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "length": len(raw_data),
        }

        ethertype = eth["ethertype"]

        # ─── ARP ───
        if ethertype == 0x0806:
            app = PacketParser.parse_arp(eth["payload"])
            packet_info["protocol"] = "ARP"
            if app:
                packet_info["src_ip"] = app["sender_ip"]
                packet_info["dst_ip"] = app["target_ip"]
                packet_info["info"] = f"ARP {app['opcode_name']}"

        # ─── IPv4 ───
        elif ethertype == 0x0800:
            ip = PacketParser.parse_ipv4(eth["payload"])
            if ip:
                packet_info["src_ip"] = ip["src_ip"]
                packet_info["dst_ip"] = ip["dst_ip"]
                packet_info["protocol"] = ip["protocol_name"]

                proto = ip["protocol"]

                # TCP
                if proto == 6:
                    transport = PacketParser.parse_tcp(ip["payload"])
                    if transport:
                        packet_info["src_port"] = transport["src_port"]
                        packet_info["dst_port"] = transport["dst_port"]
                        packet_info["tcp_flags"] = ",".join(transport["flags"])
                        packet_info["info"] = (
                            f"TCP {transport['src_port']}→{transport['dst_port']} "
                            f"[{','.join(transport['flags'])}]"
                        )
                        # Check for HTTP payload
                        if transport["payload"][:4] in (b'GET ', b'POST', b'HTTP', b'PUT ', b'HEAD'):
                            try:
                                http_line = transport["payload"].split(b'\r\n')[0].decode('ascii', errors='replace')
                                packet_info["info"] += f" | {http_line[:60]}"
                            except Exception:
                                pass

                # UDP
                elif proto == 17:
                    transport = PacketParser.parse_udp(ip["payload"])
                    if transport:
                        packet_info["src_port"] = transport["src_port"]
                        packet_info["dst_port"] = transport["dst_port"]
                        packet_info["info"] = (
                            f"UDP {transport['src_port']}→{transport['dst_port']}"
                        )
                        # DNS check
                        if transport["src_port"] == 53 or transport["dst_port"] == 53:
                            dns = PacketParser.parse_dns(transport["payload"])
                            if dns:
                                app = dns
                                direction = "Response" if dns["is_response"] else "Query"
                                packet_info["info"] += f" | DNS {direction}: {dns['query_name']}"

                # ICMP
                elif proto == 1:
                    transport = PacketParser.parse_icmp(ip["payload"])
                    if transport:
                        packet_info["info"] = (
                            f"ICMP {transport['type_name']} (type={transport['type']}, "
                            f"code={transport['code']})"
                        )

        else:
            packet_info["protocol"] = eth["ethertype_name"]
            packet_info["info"] = f"Ethertype: {eth['ethertype_name']}"

        # ─── Apply filter ───
        if self.packet_filter and not self.packet_filter.matches(packet_info):
            return

        self.packet_count += 1
        self.stats.update(packet_info)

        # ─── Display ───
        if not self.args.quiet:
            PacketDisplay.display_packet(
                self.packet_count, timestamp, eth, ip, transport, app,
                raw_data, self.args.verbose
            )

        # ─── Export ───
        if self.exporter:
            self.exporter.add_packet(packet_info)

    @staticmethod
    def _set_promisc(interface, enable):
        """Enable/disable promiscuous mode on an interface."""
        try:
            import fcntl
            SIOCGIFFLAGS = 0x8913
            SIOCSIFFLAGS = 0x8914
            IFF_PROMISC = 0x100

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack('256s', interface.encode('utf-8')[:15])
            flags = struct.unpack('16xH', fcntl.ioctl(sock, SIOCGIFFLAGS, ifreq)[:18])[0]

            if enable:
                flags |= IFF_PROMISC
                print(f"  {Colors.GREEN}[+] Promiscuous mode ENABLED on {interface}{Colors.RESET}")
            else:
                flags &= ~IFF_PROMISC
                print(f"  {Colors.GREEN}[+] Promiscuous mode DISABLED on {interface}{Colors.RESET}")

            ifreq = struct.pack('16sH', interface.encode('utf-8')[:15], flags)
            fcntl.ioctl(sock, SIOCSIFFLAGS, ifreq)
            sock.close()
        except Exception as e:
            print(f"  {Colors.YELLOW}[!] Could not set promiscuous mode: {e}{Colors.RESET}")


# ═══════════════════════════════════════════════════════════════════
# CLI Argument Parser
# ═══════════════════════════════════════════════════════════════════

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetProbe - Advanced Python Network Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          sudo python3 sniffer.py                           # Capture all traffic
          sudo python3 sniffer.py -i eth0                   # Capture on eth0
          sudo python3 sniffer.py -p TCP --port 80          # HTTP traffic only
          sudo python3 sniffer.py --ip 192.168.1.1 -v       # All traffic to/from host
          sudo python3 sniffer.py -c 100 -o capture.json    # Save 100 packets to JSON
          sudo python3 sniffer.py -p UDP --port 53 -vv      # Verbose DNS traffic
          sudo python3 sniffer.py -i wlan0 --promisc        # Promiscuous mode on wlan0
          sudo python3 sniffer.py --src-ip 10.0.0.5 -o log.csv  # Filter source + CSV export

        Output formats (auto-detected from extension):
          .json  - Full structured packet data
          .csv   - Tabular summary (timestamp, IPs, ports, protocol)
          .txt   - One-line per packet text log

        DISCLAIMER: Authorized use only. You are responsible for compliance
        with all applicable laws and regulations.
        """)
    )

    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Network interface (e.g. eth0, wlan0). Default: all')
    parser.add_argument('-c', '--count', type=int, default=None,
                        help='Number of packets to capture (default: unlimited)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase verbosity (-v normal, -vv full dump)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode: only show summary at the end')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output file (.json, .csv, .txt)')
    parser.add_argument('--promisc', action='store_true',
                        help='Enable promiscuous mode on interface')

    # Filters
    filter_group = parser.add_argument_group('Packet Filters')
    filter_group.add_argument('-p', '--protocol', type=str, default=None,
                              help='Filter by protocol (TCP, UDP, ICMP, ARP)')
    filter_group.add_argument('--src-ip', type=str, default=None,
                              help='Filter by source IP address')
    filter_group.add_argument('--dst-ip', type=str, default=None,
                              help='Filter by destination IP address')
    filter_group.add_argument('--ip', type=str, default=None,
                              help='Filter by IP (either source or destination)')
    filter_group.add_argument('--src-port', type=int, default=None,
                              help='Filter by source port')
    filter_group.add_argument('--dst-port', type=int, default=None,
                              help='Filter by destination port')
    filter_group.add_argument('--port', type=int, default=None,
                              help='Filter by port (either source or destination)')

    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    args = parse_arguments()
    sniffer = NetProbe(args)
    sniffer.start()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Synthetic PCAP Generator for SOC & Network Forensics Training.
Generates benign background traffic interleaved with a simulated periodic beacon
and a harmless dummy ELF binary artifact for carving practice.
"""

import random
import base64
import struct
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
)

# ==============================================================================
# CONFIGURATION & DIFFICULTY TUNING
# ==============================================================================
OUTPUT_FILE = "/Users/tosin/Python Development/TaskNewDawn/starting_capture.pcap"
START_TIME = 1700000000.0  # Base epoch timestamp

# Network Addresses (RFC 1918 Private & RFC 5737 Documentation Ranges)
INTERNAL_HOSTS = ["10.10.15.22", "10.10.15.45", "10.10.15.88"]
COMPROMISED_HOST = "10.10.15.45"
DNS_SERVER = "10.10.15.1"

BENIGN_SERVERS = ["192.0.2.10", "198.51.100.25", "203.0.113.50"]
ANOMALY_SERVER = "198.51.100.99"

# Traffic Volume & Timing Controls
NUM_BENIGN_FLOWS = 45       # Increase for more background noise
BEACON_COUNT = 12           # Number of periodic check-ins
BEACON_INTERVAL = 30.0      # Seconds between beacons
BEACON_JITTER = 2.5         # +/- seconds of timing variance
ANOMALY_PORT = 8443         # Non-standard destination port

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def build_dummy_elf() -> bytes:
    """
    Constructs a minimal, non-executable dummy ELF binary containing harmless
    training strings so analysts can carve and inspect it in Ghidra/strings.
    """
    # Standard 64-bit ELF Header (64 bytes)
    elf_header = (
        b"\x7fELF"                      # Magic
        b"\x02"                          # 64-bit
        b"\x01"                          # Little endian
        b"\x01"                          # ELF version
        b"\x00" * 9                      # OS/ABI + Padding
        + struct.pack("<H", 2)           # e_type: ET_EXEC
        + struct.pack("<H", 0x3E)        # e_machine: x86-64
        + struct.pack("<I", 1)           # e_version
        + struct.pack("<Q", 0x401000)    # e_entry
        + struct.pack("<Q", 64)          # e_phoff
        + struct.pack("<Q", 0)           # e_shoff
        + struct.pack("<I", 0)           # e_flags
        + struct.pack("<H", 64)          # e_ehsize
        + struct.pack("<H", 56)          # e_phentsize
        + struct.pack("<H", 1)           # e_phnum
        + struct.pack("<H", 0)           # e_shentsize
        + struct.pack("<H", 0)           # e_shnum
        + struct.pack("<H", 0)           # e_shstrndx
    )

    # Minimal Program Header (56 bytes)
    prog_header = (
        struct.pack("<I", 1)             # p_type: PT_LOAD
        + struct.pack("<I", 5)           # p_flags: R-X
        + struct.pack("<Q", 0)           # p_offset
        + struct.pack("<Q", 0x400000)    # p_vaddr
        + struct.pack("<Q", 0x400000)    # p_paddr
        + struct.pack("<Q", 512)         # p_filesz
        + struct.pack("<Q", 512)         # p_memsz
        + struct.pack("<Q", 0x1000)      # p_align
    )

    # Harmless payload / artifacts for static analysis
    artifacts = (
        b"\x90" * 16 + b"\xc3"           # NOP sled + RET (safe stub)
        b"\x00TRAINING_ARTIFACT_START\x00"
        b"CFG_HOST=198.51.100.99:8443\x00"
        b"USER_AGENT=TelemetryAgent/1.0\x00"
        b"KEY_HINT=XOR_0x55\x00"
        b"TRAINING_ARTIFACT_END\x00"
    )
    padding = b"\x00" * (512 - len(elf_header) - len(prog_header) - len(artifacts))
    return elf_header + prog_header + artifacts + padding


def create_tcp_exchange(src_ip, dst_ip, sport, dport, payload_out, payload_in, ts):
    """Generates a 3-way handshake, data transfer, and teardown with timestamps."""
    pkts = []
    seq_c = random.randint(10000, 90000)
    seq_s = random.randint(10000, 90000)

    # SYN
    p1 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c)
    p1.time = ts
    pkts.append(p1)

    # SYN-ACK
    ts += 0.015
    p2 = Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1)
    p2.time = ts
    pkts.append(p2)

    # ACK
    ts += 0.005
    p3 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)
    p3.time = ts
    pkts.append(p3)

    # Outbound Data
    if payload_out:
        ts += 0.020
        p4 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(load=payload_out)
        p4.time = ts
        pkts.append(p4)
        seq_c += len(payload_out)

    # Inbound Response
    if payload_in:
        ts += 0.045
        p5 = Ether() / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1) / Raw(load=payload_in)
        p5.time = ts
        pkts.append(p5)
        seq_s += len(payload_in)

    # FIN-ACK teardown
    ts += 0.010
    p6 = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c + 1, ack=seq_s + 1)
    p6.time = ts
    pkts.append(p6)

    return pkts, ts


# ==============================================================================
# TRAFFIC GENERATION
# ==============================================================================

def generate_capture():
    all_packets = []
    domains = ["portal.corp.example", "updates.vendor.test", "cdn.media.example", "docs.internal.test"]

    # 1. Generate Benign Background Noise (DNS, HTTP, Keepalives)
    current_time = START_TIME
    for _ in range(NUM_BENIGN_FLOWS):
        host = random.choice(INTERNAL_HOSTS)
        server = random.choice(BENIGN_SERVERS)
        domain = random.choice(domains)
        flow_type = random.choice(["dns", "http", "keepalive"])

        if flow_type == "dns":
            sport = random.randint(49152, 65535)
            tx_id = random.randint(1, 65535)
            q = Ether() / IP(src=host, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / DNS(id=tx_id, rd=1, qd=DNSQR(qname=domain))
            q.time = current_time
            r = Ether() / IP(src=DNS_SERVER, dst=host) / UDP(sport=53, dport=sport) / DNS(
                id=tx_id, qr=1, aa=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, ttl=300, rdata=server)
            )
            r.time = current_time + 0.012
            all_packets.extend([q, r])

        elif flow_type == "http":
            sport = random.randint(49152, 65535)
            req = f"GET /index.html HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
            resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nStatus: Alive"
            pkts, _ = create_tcp_exchange(host, server, sport, 80, req, resp, current_time)
            all_packets.extend(pkts)

        elif flow_type == "keepalive":
            sport = random.randint(49152, 65535)
            ka = Ether() / IP(src=host, dst=server) / TCP(sport=sport, dport=443, flags="A", seq=1000, ack=2000)
            ka.time = current_time
            ka_ack = Ether() / IP(src=server, dst=host) / TCP(sport=443, dport=sport, flags="A", seq=2000, ack=1001)
            ka_ack.time = current_time + 0.025
            all_packets.extend([ka, ka_ack])

        current_time += random.uniform(3.0, 14.0)

    # 2. Generate Interleaved Anomalous Beacon & Artifact Delivery
    anomaly_start = START_TIME + 45.0  # Starts after initial baseline noise
    beacon_time = anomaly_start
    anomaly_pkt_count = 0

    for i in range(BEACON_COUNT):
        sport = random.randint(49152, 65535)
        raw_status = f"ID=HOST02|SEQ={i}|STAT=OK".encode()
        encoded_beacon = b"CHK:" + base64.b64encode(raw_status)

        # On beacon #5, deliver the dummy ELF artifact inside an HTTP-like response
        if i == 5:
            elf_bytes = build_dummy_elf()
            server_reply = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                + f"Content-Length: {len(elf_bytes)}\r\n\r\n".encode()
                + elf_bytes
            )
        else:
            server_reply = b"ACK:" + base64.b64encode(b"SLEEP")

        pkts, _ = create_tcp_exchange(
            COMPROMISED_HOST, ANOMALY_SERVER, sport, ANOMALY_PORT, encoded_beacon, server_reply, beacon_time
        )
        all_packets.extend(pkts)
        anomaly_pkt_count += len(pkts)

        # Advance by fixed interval + jitter
        beacon_time += BEACON_INTERVAL + random.uniform(-BEACON_JITTER, BEACON_JITTER)

    # 3. Sort Chronologically & Write PCAP
    all_packets.sort(key=lambda pkt: pkt.time)
    wrpcap(OUTPUT_FILE, all_packets)

    # 4. Print Ground Truth Summary
    print("=" * 60)
    print(f"PCAP Generated: {OUTPUT_FILE}")
    print("=" * 60)
    print(f"Total Packets:       {len(all_packets)}")
    print(f"Capture Duration:    {all_packets[-1].time - all_packets[0].time:.2f} seconds")
    print("-" * 60)
    print("GROUND TRUTH SUMMARY:")
    print(f"  Benign Hosts:      {', '.join(INTERNAL_HOSTS)}")
    print(f"  Benign Servers:    {', '.join(BENIGN_SERVERS)} (Ports 53, 80, 443)")
    print(f"  Anomalous Flow:    {COMPROMISED_HOST} -> {ANOMALY_SERVER}:{ANOMALY_PORT}")
    print(f"  Beacon Pattern:    {BEACON_COUNT} sessions, ~{BEACON_INTERVAL}s interval (+/- {BEACON_JITTER}s jitter)")
    print(f"  Anomaly Packets:   ~{anomaly_pkt_count} packets interleaved starting at +{anomaly_start - START_TIME:.1f}s")
    print(f"  Embedded Artifact: Dummy 64-bit ELF binary (512 bytes) in Beacon #5 response")
    print("=" * 60)


if __name__ == "__main__":
    generate_capture()

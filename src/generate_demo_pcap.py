#!/usr/bin/env python3
"""Generate a small PCAP containing normal DNS and DNS-tunnel-like traffic.

No packet library is required; this writes Ethernet/IPv4/UDP/DNS frames directly.
"""
from __future__ import annotations

import argparse
import random
import socket
import struct
import time
from pathlib import Path

from common import TUNNEL_DOMAIN, b32_encode, chunk_text, random_session_id

NORMAL_DOMAINS = [
    "www.uni.lu",
    "moodle.uni.lu",
    "www.wikipedia.org",
    "www.cloudflare.com",
    "www.python.org",
]
MESSAGES = [
    "ping: hello through DNS",
    "GET /index.html HTTP/1.1 Host: example.local",
    "file-transfer-demo: username=student; token=lab-only; line=1",
    "remote-command-demo: whoami",
]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def encode_qname(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(qname: str, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_qname(qname) + struct.pack("!HH", 1, 1)
    return header + question


def dns_response(qname: str, txid: int, answer_ip: str) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x8580, 1, 1, 0, 0)
    question = encode_qname(qname) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton(answer_ip)
    return header + question + answer


def udp_ipv4_frame(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    version_ihl = 0x45
    total_len = 20 + len(udp)
    ip_id = random.randint(0, 65535)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_len,
        ip_id,
        0,
        64,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", 0x0800)
    return eth + ip_header + udp


def dns_pair(src: str, dst: str, sport: int, qname: str, txid: int, answer: str = "10.10.10.10"):
    return [
        udp_ipv4_frame(src, dst, sport, 53, dns_query(qname, txid)),
        udp_ipv4_frame(dst, src, 53, sport, dns_response(qname, txid, answer)),
    ]


def write_pcap(path: Path, frames: list[bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = time.time()
        for i, frame in enumerate(frames):
            t = ts + i * 0.01
            sec = int(t)
            usec = int((t - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create demo_dns_tunnel.pcap")
    parser.add_argument("--output", default="pcaps/demo_dns_tunnel.pcap")
    parser.add_argument("--domain", default=TUNNEL_DOMAIN)
    parser.add_argument("--tunnel-count", type=int, default=80)
    args = parser.parse_args()

    frames = []
    client = "192.0.2.20"
    dns_server = "192.0.2.53"
    txid = 1000

    for i in range(30):
        domain = random.choice(NORMAL_DOMAINS)
        frames.extend(dns_pair(client, dns_server, 40000 + i, domain, txid, "93.184.216.34"))
        txid += 1

    session = random_session_id()
    for i in range(args.tunnel_count):
        msg = MESSAGES[i % len(MESSAGES)] + f" counter={i:03d}"
        encoded = b32_encode(msg.encode("utf-8"))
        for label in chunk_text(encoded, 50):
            qname = f"{label}.{i:03d}.{session}.{args.domain}"
            frames.extend(dns_pair(client, dns_server, 41000 + (i % 1000), qname, txid))
            txid += 1

    out = Path(args.output)
    write_pcap(out, frames)
    print(f"Wrote {len(frames)} packets to {out}")


if __name__ == "__main__":
    main()

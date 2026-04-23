#!/usr/bin/env python3
"""Client for the local DNS-based communication lab."""
from __future__ import annotations

import argparse
import socket
import time
from pathlib import Path

from dnslib import DNSRecord

from common import DEFAULT_DNS_PORT, TUNNEL_DOMAIN, b32_encode, chunk_text, random_session_id


def send_query(server: str, port: int, qname: str, timeout: float = 2.0) -> str:
    packet = DNSRecord.question(qname, "A")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet.pack(), (server, port))
        data, _ = sock.recvfrom(4096)
        response = DNSRecord.parse(data)
        return str(response.rr[0].rdata) if response.rr else "<no answer>"
    finally:
        sock.close()


def build_qnames(message: str, domain: str, session: str) -> list[str]:
    encoded = b32_encode(message.encode("utf-8"))
    labels = chunk_text(encoded, 50)
    # Put sequence and session labels near the tunnel suffix. Long/random labels are intentional for detection.
    return [f"{label}.{i:03d}.{session}.{domain}" for i, label in enumerate(labels, start=1)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate DNS tunnel-like queries to localhost")
    parser.add_argument("--server", default="127.0.0.1", help="DNS server IP")
    parser.add_argument("--port", type=int, default=DEFAULT_DNS_PORT, help="DNS server port")
    parser.add_argument("--domain", default=TUNNEL_DOMAIN, help="Tunnel domain suffix")
    parser.add_argument("--message", default="ping: hello through DNS", help="Message to encode into DNS labels")
    parser.add_argument("--file", help="Optional file to send as DNS-label chunks")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat message N times to increase query frequency")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between queries")
    parser.add_argument("--session", default=random_session_id(), help="Session identifier label")
    args = parser.parse_args()

    if args.file:
        message = Path(args.file).read_text(encoding="utf-8", errors="replace")
    else:
        message = args.message

    sent = 0
    for r in range(args.repeat):
        for qname in build_qnames(message, args.domain, args.session):
            answer = send_query(args.server, args.port, qname)
            sent += 1
            print(f"{sent:04d} {qname} -> {answer}")
            time.sleep(args.delay)
    print(f"Done. Sent {sent} DNS queries in session {args.session}.")


if __name__ == "__main__":
    main()

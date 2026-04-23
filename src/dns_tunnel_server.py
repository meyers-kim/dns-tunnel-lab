#!/usr/bin/env python3
"""
Safe local DNS-based communication server for the Wireshark DNS tunneling lab.

It listens only on 127.0.0.1 by default and decodes Base32 data embedded in
subdomains under tunnel.lab. This demonstrates DNS tunneling indicators without
opening a real remote shell or external covert channel.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR
from dnslib.server import BaseResolver, DNSServer

from common import DEFAULT_DNS_PORT, TUNNEL_DOMAIN, b32_decode


class TunnelResolver(BaseResolver):
    def __init__(self, domain: str, log_file: Path):
        self.domain = domain.rstrip(".").lower()
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def resolve(self, request: DNSRecord, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()
        decoded = ""
        status_ip = "10.10.10.10"

        if qname.endswith(self.domain):
            prefix = qname[: -(len(self.domain))].rstrip(".")
            labels = [x for x in prefix.split(".") if x]
            encoded = "".join(labels[:-2]) if len(labels) >= 2 else ""  # msg labels before seq/session
            try:
                if encoded:
                    decoded = b32_decode(encoded).decode("utf-8", errors="replace")
            except Exception as exc:  # intentionally broad for lab robustness
                decoded = f"<decode error: {exc}>"
                status_ip = "10.10.10.99"

            line = f"{datetime.utcnow().isoformat()}Z qtype={qtype} qname={qname} decoded={decoded!r}\n"
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line)
            print(line, end="")
        else:
            status_ip = "10.10.10.53"

        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(status_ip), ttl=1))
        return reply


def main() -> None:
    parser = argparse.ArgumentParser(description="Local DNS tunnel demonstration server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address; default is localhost only")
    parser.add_argument("--port", type=int, default=DEFAULT_DNS_PORT, help="UDP DNS port")
    parser.add_argument("--domain", default=TUNNEL_DOMAIN, help="Tunnel domain suffix")
    parser.add_argument("--log", default="reports/server-decoded.log", help="Decoded message log path")
    args = parser.parse_args()

    resolver = TunnelResolver(args.domain, Path(args.log))
    server = DNSServer(resolver, port=args.port, address=args.host, tcp=False)
    print(f"Listening on udp://{args.host}:{args.port} for *.{args.domain}")
    print("Press Ctrl+C to stop.")
    server.start_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()

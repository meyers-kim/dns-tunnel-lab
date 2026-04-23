#!/usr/bin/env python3
"""Analyze DNS PCAP files for tunneling indicators without external packet libraries."""
from __future__ import annotations

import argparse
import struct
from collections import Counter, defaultdict

from common import shannon_entropy


def iter_pcap_frames(path: str):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) != 24:
            return
        magic = gh[:4]
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            _sec, _usec, incl_len, _orig_len = struct.unpack(endian + "IIII", ph)
            data = f.read(incl_len)
            if len(data) == incl_len:
                yield data


def decode_dns_name(data: bytes, offset: int, depth: int = 0):
    labels = []
    jumped = False
    end_offset = offset
    if depth > 5:
        return "<compression-loop>", offset + 1
    while offset < len(data):
        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            return ".".join(labels), end_offset
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return "<bad-pointer>", offset + 1
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = decode_dns_name(data, pointer, depth + 1)
            labels.append(suffix)
            if not jumped:
                end_offset = offset + 2
            return ".".join(x for x in labels if x), end_offset
        offset += 1
        label = data[offset : offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length
    return "<truncated>", offset


def extract_dns_queries(frame: bytes):
    # Ethernet + IPv4 + UDP only, enough for this lab and tcpdump captures on Ethernet-like links.
    if len(frame) < 42:
        return []
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != 0x0800:
        return []
    ip_start = 14
    ihl = (frame[ip_start] & 0x0F) * 4
    proto = frame[ip_start + 9]
    if proto != 17:
        return []
    udp_start = ip_start + ihl
    if len(frame) < udp_start + 8:
        return []
    sport, dport, _ulen, _sum = struct.unpack("!HHHH", frame[udp_start : udp_start + 8])
    if sport != 53 and dport != 53 and sport != 5353 and dport != 5353:
        return []
    dns = frame[udp_start + 8 :]
    if len(dns) < 12:
        return []
    _txid, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!HHHHHH", dns[:12])
    qr = flags & 0x8000
    if qr:
        return []
    offset = 12
    names = []
    for _ in range(qdcount):
        name, offset = decode_dns_name(dns, offset)
        if offset + 4 > len(dns):
            break
        _qtype, _qclass = struct.unpack("!HH", dns[offset : offset + 4])
        offset += 4
        names.append(name.lower().rstrip("."))
    return names


def registered_like_suffix(qname: str) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname.rstrip(".")


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect DNS tunneling indicators in a PCAP")
    parser.add_argument("pcap", help="Input .pcap")
    parser.add_argument("--domain", default="tunnel.lab", help="Expected tunnel domain, if known")
    parser.add_argument("--long-label", type=int, default=45)
    parser.add_argument("--entropy", type=float, default=3.5)
    args = parser.parse_args()

    queries = []
    for frame in iter_pcap_frames(args.pcap):
        queries.extend(extract_dns_queries(frame))

    suffix_counts = Counter(registered_like_suffix(q) for q in queries)
    qname_counts = Counter(queries)
    suspicious = []
    by_suffix_suspicious = defaultdict(int)

    for q in queries:
        labels = q.split(".")
        max_label = max(labels, key=len)
        ent = shannon_entropy(max_label)
        reasons = []
        if len(max_label) >= args.long_label:
            reasons.append(f"long label={len(max_label)}")
        if ent >= args.entropy and len(max_label) >= 20:
            reasons.append(f"high entropy={ent:.2f}")
        if q.endswith(args.domain):
            reasons.append(f"known tunnel suffix={args.domain}")
        if reasons:
            suspicious.append((q, "; ".join(reasons), len(max_label), ent))
            by_suffix_suspicious[registered_like_suffix(q)] += 1

    print("=== DNS PCAP analysis ===")
    print(f"PCAP: {args.pcap}")
    print(f"Total DNS queries: {len(queries)}")
    print("\nTop queried suffixes:")
    for suffix, count in suffix_counts.most_common(10):
        print(f"  {suffix:30s} {count}")

    print("\nMost suspicious suffixes:")
    for suffix, count in Counter(by_suffix_suspicious).most_common(10):
        print(f"  {suffix:30s} {count} suspicious queries")

    print("\nSample suspicious queries:")
    for q, reason, _label_len, _ent in suspicious[:15]:
        print(f"  {q}  [{reason}]")

    repeated = [(q, c) for q, c in qname_counts.most_common() if c > 1]
    print("\nRepeated exact query names:")
    if repeated:
        for q, c in repeated[:10]:
            print(f"  {c}x {q}")
    else:
        print("  None. DNS tunnels often use unique subdomains but a repeated suffix/domain.")

    print("\nLikely tunnel domain:")
    if by_suffix_suspicious:
        print(f"  {Counter(by_suffix_suspicious).most_common(1)[0][0]}")
    else:
        print("  Not detected with current thresholds.")


if __name__ == "__main__":
    main()

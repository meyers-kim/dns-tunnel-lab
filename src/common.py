#!/usr/bin/env python3
"""Shared helpers for the local DNS tunneling lab."""
from __future__ import annotations

import base64
import math
import random
import string
from dataclasses import dataclass

TUNNEL_DOMAIN = "tunnel.lab"
DEFAULT_DNS_PORT = 5353


def b32_encode(data: bytes) -> str:
    """DNS-label-safe Base32 without padding, lowercase."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def b32_decode(text: str) -> bytes:
    """Decode lowercase/uppercase Base32 label text without padding."""
    text = text.strip().upper()
    padding = "=" * ((8 - len(text) % 8) % 8)
    return base64.b32decode(text + padding)


def chunk_text(text: str, size: int = 50) -> list[str]:
    """Split a string into DNS-label-sized chunks."""
    return [text[i : i + size] for i in range(0, len(text), size)] or [""]


def random_session_id(length: int = 6) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


@dataclass
class SuspiciousQuery:
    qname: str
    reason: str
    label_len: int
    entropy: float

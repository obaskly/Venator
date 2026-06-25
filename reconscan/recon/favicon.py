"""Favicon fingerprinting via the Shodan-style mmh3 hash (pure-Python).

The favicon at /favicon.ico is identical across every deployment of a given
app/version, so its hash is a stable fingerprint that pivots — paste it into
Shodan (`http.favicon.hash:<h>`) or FOFA to find sibling hosts and origin
servers that no DNS brute will ever surface. We compute MurmurHash3 (x86 32-bit,
signed) over the base64 of the icon, exactly like the `mmh3` library Shodan uses,
so no third-party dependency is needed.
"""
from __future__ import annotations

import base64
from typing import Optional
from urllib.parse import urljoin

from ..http import Client
from ..utils import log


def _murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = (length & ~3)

    def rotl(x, r):
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

    for i in range(0, rounded, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24))
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = rotl(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = rotl(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = rotl(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # to signed 32-bit (matches mmh3.hash)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(client: Client, base_url: str) -> Optional[dict]:
    r = client.get(urljoin(base_url, "/favicon.ico"), phase="fingerprint")
    if not r.ok or r.status != 200:
        return None
    ctype = r.headers.get("content-type", "")
    raw = (r.text or "").encode("latin-1", errors="ignore")
    if not raw or ("image" not in ctype and "icon" not in ctype):
        return None
    b64 = base64.encodebytes(raw)  # newline-wrapped, like the mmh3 recipe
    h = _murmur3_x86_32(b64)
    info = {
        "hash": h,
        "shodan": f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}",
        "fofa_query": f'icon_hash="{h}"',
    }
    log("ok", f"favicon hash: {h} (pivot: Shodan http.favicon.hash:{h})")
    return info

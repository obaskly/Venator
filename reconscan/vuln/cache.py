"""Web cache poisoning + host-header injection detection (non-destructive).

Sends unkeyed request headers (X-Forwarded-Host, X-Forwarded-Scheme, X-Host,
X-Original-URL, Host overrides) carrying a unique canary, and checks whether the
canary is reflected into the response. If the endpoint is ALSO cacheable, that's
a cache-poisoning candidate; if only reflected, it's host-header injection.

Safety: every probe carries a unique cache-buster query param so we never write
to the real (shared) cache key — we only observe reflection on our own throwaway
key. Read-only GETs.

Ref: https://portswigger.net/web-security/web-cache-poisoning
"""
from __future__ import annotations

import secrets
from typing import List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..http import Client
from ..utils import log
from . import Finding

# (header, value-template{C}) — {C} replaced with the canary host.
_UNKEYED = [
    ("X-Forwarded-Host", "{C}"),
    ("X-Forwarded-Server", "{C}"),
    ("X-Host", "{C}"),
    ("X-Forwarded-Scheme", "http"),         # downgrade reflection
    ("X-Original-URL", "/{C}"),
    ("X-Rewrite-URL", "/{C}"),
]
_CACHE_HINTS = ("cf-cache-status", "x-cache", "x-cache-hits", "age",
                "x-served-by", "x-vercel-cache", "x-nextjs-cache")


def _cachebust(url: str) -> str:
    pr = urlparse(url)
    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
    qs["cb"] = secrets.token_hex(6)
    return urlunparse(pr._replace(query=urlencode(qs)))


def _cacheable(headers: dict) -> bool:
    cc = headers.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc or "max-age" in cc and "max-age=0" not in cc:
        return True
    return any(h in headers for h in _CACHE_HINTS)


def check(client: Client, base_urls: List[str]) -> List[Finding]:
    if not base_urls:
        return []
    log("info", f"cache-poisoning / host-header probe on {len(base_urls)} base URL(s)")
    findings: List[Finding] = []

    for base in base_urls:
        for header, tmpl in _UNKEYED:
            canary = f"rcp{secrets.token_hex(4)}.example.com"
            value = tmpl.replace("{C}", canary)
            test = _cachebust(base)
            r = client.get(test, phase="active", allow_redirects=False,
                           extra_headers={header: value})
            if not r.ok:
                continue
            body = r.text or ""
            loc = r.headers.get("location", "")
            reflected = (canary in body) or (canary in loc)
            if not reflected:
                continue
            cacheable = _cacheable(r.headers)
            where = "Location" if canary in loc else "body"
            if cacheable:
                findings.append(Finding(
                    title=f"Web cache poisoning candidate via {header}",
                    severity="high", category="cache", target=base,
                    evidence=f"unkeyed '{header}: {value}' reflected in {where}; "
                             f"response appears cacheable "
                             f"(cache-control={r.headers.get('cache-control','-')}, "
                             f"{[h for h in _CACHE_HINTS if h in r.headers]})",
                    recommendation=("Confirm the poisoned response is served to other "
                                    "users from cache (use the program's rules; do not "
                                    "poison shared prod cache). Add the header to Vary "
                                    "or stop reflecting it."),
                    confidence="tentative"))
                log("vuln", f"[high] cache poisoning candidate: {header} @ {base}")
            else:
                findings.append(Finding(
                    title=f"Host-header injection via {header}",
                    severity="medium", category="cache", target=base,
                    evidence=f"unkeyed '{header}: {value}' reflected in {where} "
                             f"(no obvious cache) ",
                    recommendation=("Check for password-reset poisoning / open-redirect "
                                    "/ SSRF impact. Validate Host and stop trusting "
                                    "X-Forwarded-* for URL generation."),
                    confidence="tentative"))
                log("vuln", f"[medium] host-header injection: {header} @ {base}")
            break  # one reflecting header per base is enough to flag
    return findings

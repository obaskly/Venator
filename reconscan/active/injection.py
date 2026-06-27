"""Error/signature-based injection leads (benign, non-destructive).

For in-scope URLs with parameters (plus a tiny common-param set), probe each
parameter for:
  * SQLi   — append a quote breaker, look for SQL error strings (no UNION/OR/time)
  * SSTI   — inject a marker+{{7*7}}, look for marker+49 rendered (no code exec)
  * LFI/traversal — request /etc/passwd style, look for real file signatures
  * reflected XSS context — inject a raw-metachar marker, see if < > survive

Every check is anchored to a per-(url,param) BASELINE response: a signal only
counts if it appears in the payload response and NOT in the benign baseline.
This kills the dominant false-positive source — SPA shells (e.g. Next.js) that
return an identical 200 and reflect the input for every route. SSTI uses a random
marker concatenated with the payload so a stray "49" in the page can't trigger it.

These confirm a bug CLASS exists; they do not exploit it. No payload modifies
data. Request volume is capped hard to stay polite.
"""
from __future__ import annotations

import secrets
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..config import Config
from ..data import (SQLI_PROBES, SQL_ERROR_SIGNS, SSTI_PROBES, TRAVERSAL_PROBES,
                    TRAVERSAL_SIGNS)
from ..http import Client
from ..utils import dedup_keep_order, log
from ..vuln import Finding

_COMMON_PARAMS = ["q", "id", "search", "page"]
_MAX_URLS = 10
_MAX_PARAMS = 4
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map", ".txt", ".xml", ".webp", ".mp4")


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[param] = value
    return urlunparse(parts._replace(query=urlencode(qs)))


def _params_for(url: str) -> List[str]:
    existing = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    return dedup_keep_order(existing or _COMMON_PARAMS)[:_MAX_PARAMS]


def _is_static(url: str) -> bool:
    return urlparse(url).path.lower().endswith(_STATIC_EXT)


def _targets(base_urls: List[str], discovered: List[dict]) -> List[str]:
    urls = list(base_urls)
    with_q = [d["url"] for d in discovered if "?" in d.get("url", "")]
    without_q = [d["url"] for d in discovered if "?" not in d.get("url", "")]
    urls += with_q + without_q
    urls = [u for u in dedup_keep_order(urls) if not _is_static(u)]
    return urls[:_MAX_URLS]


def _sqli(client, url, param, baseline_low) -> Optional[Finding]:
    for probe in SQLI_PROBES[:3]:
        r = client.get(_set_param(url, param, "recon" + probe), phase="active")
        if not r.ok:
            continue
        low = (r.text or "").lower()
        for sign in SQL_ERROR_SIGNS:
            if sign in low and sign not in baseline_low:
                return Finding(
                    title=f"Possible SQL injection (error-based) in '{param}'",
                    severity="high", category="sqli", target=_set_param(url, param, "…"),
                    evidence=f"DB error '{sign}' surfaced after appending {probe!r} to "
                             f"'{param}' (absent from baseline)",
                    recommendation=("Error-based SQLi lead — the exploitation phase "
                                    "auto-confirms it with a boolean/error oracle and "
                                    "attaches a PoC. Parameterize the query. High impact."),
                    confidence="firm")
    return None


def _ssti(client, url, param, baseline_low) -> Optional[Finding]:
    marker = "rcs" + secrets.token_hex(3)
    for expr, expected in SSTI_PROBES[:3]:
        r = client.get(_set_param(url, param, marker + expr), phase="active")
        if not r.ok:
            continue
        body = r.text or ""
        rendered = marker + expected          # e.g. rcsab12 + 49
        echoed = marker + expr                # e.g. rcsab12 + {{7*7}}
        if rendered in body and echoed not in body:
            return Finding(
                title=f"Possible server-side template injection in '{param}'",
                severity="high", category="ssti", target=_set_param(url, param, expr),
                evidence=f"template expr {expr!r} rendered (marker {marker!r} -> "
                         f"{rendered!r}, raw payload not echoed)",
                recommendation=("Template expression rendered — the exploitation phase "
                                "auto-confirms the engine and escalates toward RCE. "
                                "Sandbox/escape all template input."),
                confidence="firm")
    return None


def _traversal(client, url, param, baseline_low) -> Optional[Finding]:
    for probe in TRAVERSAL_PROBES[:3]:
        r = client.get(_set_param(url, param, probe), phase="active")
        if not r.ok:
            continue
        low = (r.text or "").lower()
        for sign in TRAVERSAL_SIGNS:
            if sign in low and sign not in baseline_low:
                return Finding(
                    title=f"Possible path traversal / LFI in '{param}'",
                    severity="high", category="lfi", target=_set_param(url, param, probe),
                    evidence=f"file signature {sign!r} returned for payload {probe!r} "
                             f"(absent from baseline)",
                    recommendation=("File-read confirmed by signature — the exploitation "
                                    "phase probes the read scope and attaches proof. "
                                    "Restrict to an allowlist; never pass user input to "
                                    "file paths."),
                    confidence="firm")
    return None


def _xss_ctx(client, url, param, baseline_low) -> Optional[Finding]:
    marker = "rcx" + secrets.token_hex(3)
    payload = f"{marker}<svg/onload=1>"
    r = client.get(_set_param(url, param, payload), phase="active")
    if not r.ok:
        return None
    ctype = r.headers.get("content-type", "").lower()
    # raw, unescaped reflection of < > in an HTML response
    if "html" in ctype and payload in (r.text or "") and payload not in baseline_low:
        return Finding(
            title=f"Reflected XSS context (raw HTML metachars) in '{param}'",
            severity="medium", category="xss", target=_set_param(url, param, payload),
            evidence=f"marker reflected with UNescaped <,>: {payload!r} in HTML response",
            recommendation=("Raw metachars reflected — the exploitation phase auto-confirms "
                            "execution with breaking vectors and attaches a PoC URL. Apply "
                            "context-aware output encoding."),
            confidence="firm")
    return None


def check(client: Client, base_urls: List[str], discovered: List[dict],
          cfg: Config) -> List[Finding]:
    targets = _targets(base_urls, discovered)
    if not targets:
        return []
    log("info", f"injection leads on {len(targets)} URL(s) (sqli/ssti/lfi/xss)")
    findings: List[Finding] = []
    for url in targets:
        for param in _params_for(url):
            # benign baseline for this (url,param): random inert value
            base = client.get(_set_param(url, param, "recon" + secrets.token_hex(4)),
                              phase="active")
            baseline_low = (base.text or "").lower() if base.ok else ""
            for probe_fn in (_sqli, _ssti, _traversal, _xss_ctx):
                f = probe_fn(client, url, param, baseline_low)
                if f:
                    findings.append(f)
                    log("vuln", f"[{f.severity}] {f.category} lead: {param} @ {url}")
    return findings

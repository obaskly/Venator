"""CRLF injection / HTTP response-header splitting detection (read-only).

Injects percent-encoded CR/LF sequences into request parameters (and the path)
that commonly feed response headers — redirect/url/return params, etc. — and
confirms ONLY when a uniquely-named header we asked the server to emit shows up
as a REAL parsed response header carrying our exact random token.

That confirmation is unambiguous: a header named `x-crlf-<rand>` with value
`<rand>` can only appear if the server split our value into a new header, so
there are effectively no false positives. We never follow the redirect and send
nothing destructive — the split header is benign.
"""
from __future__ import annotations

import secrets
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse

from ..config import Config
from ..data import REDIRECT_PARAMS
from ..http import Client
from ..utils import log
from ..vuln import Finding

# params most likely to be reflected into a Location / Set-Cookie / header
_CRLF_PARAMS = REDIRECT_PARAMS[:12] + ["lang", "page", "q", "view", "file", "host"]


def _payloads(header: str, token: str) -> List[Tuple[str, str]]:
    """(label, raw-percent-encoded value). Value starts with a benign '1' so it
    stays a plausible param value, then carries the CR/LF split."""
    h, t = header, token
    sc = f"Set-Cookie:{t}=1"
    return [
        ("CRLF", f"1%0d%0a{h}:{t}"),
        ("LF-only", f"1%0a{h}:{t}"),
        ("CRLF Set-Cookie", f"1%0d%0a{sc}"),
        ("double-encoded", f"1%250d%250a{h}:{t}"),
        # overlong UTF-8 (嘊嘍) — some stacks decode to CR/LF (Firefox-style strip)
        ("utf8-overlong", f"1%E5%98%8A%E5%98%8D{h}:{t}"),
        ("CR+space", f"1%0d%20{h}:{t}"),
    ]


def _raw_param_url(url: str, param: str, raw_value: str) -> str:
    """Append `param=raw_value` to the query WITHOUT re-encoding raw_value (the
    payload is already percent-encoded; urlencode would double-encode the %)."""
    pr = urlparse(url)
    q = pr.query
    frag = f"{param}={raw_value}"
    new_q = f"{q}&{frag}" if q else frag
    return urlunparse(pr._replace(query=new_q))


def _confirmed(r, header: str, token: str) -> str:
    """Return the proof string if the split header landed as a real header."""
    if not r.ok:
        return ""
    # our custom header reflected verbatim
    val = r.headers.get(header.lower())
    if val is not None and token in val:
        return f"{header}: {val}"
    # Set-Cookie split
    sc = r.headers.get("set-cookie", "")
    if f"{token}=1" in sc:
        return f"Set-Cookie: {sc}"
    return ""


def check(client: Client, base_urls: List[str], cfg: Config) -> List[Finding]:
    if not base_urls:
        return []
    log("info", f"CRLF / response-splitting probe on {len(base_urls)} base URL(s)")
    findings: List[Finding] = []

    for base in base_urls:
        if cfg.max_requests and client.over_budget():
            break
        token = "crlf" + secrets.token_hex(4)
        header = "X-Crlf-" + token
        pr = urlparse(base)
        root = f"{pr.scheme}://{pr.netloc}"
        hit = None

        # 1) path-based injection: server reflecting the request path into a header
        for label, val in _payloads(header, token)[:3]:
            test = f"{root}/{val}"
            r = client.get(test, phase="active", allow_redirects=False)
            proof = _confirmed(r, header, token)
            if proof:
                hit = (f"path ({label})", test, proof, r.status)
                break

        # 2) parameter-based injection
        if not hit:
            for param in _CRLF_PARAMS:
                for label, val in _payloads(header, token):
                    test = _raw_param_url(base, param, val)
                    r = client.get(test, phase="active", allow_redirects=False)
                    proof = _confirmed(r, header, token)
                    if proof:
                        hit = (f"param '{param}' ({label})", test, proof, r.status)
                        break
                if hit:
                    break

        if hit:
            technique, test_url, proof, code = hit
            findings.append(Finding(
                title="CRLF injection / HTTP response-header splitting",
                severity="high", category="crlf", target=test_url,
                evidence=(f"injected CR/LF via {technique} made the server emit an "
                          f"attacker-controlled response header (status {code}): "
                          f"{proof[:160]}"),
                recommendation=("Strip/encode CR and LF in any user input that reaches "
                                "response headers (redirect targets, cookies). Impact: "
                                "Set-Cookie injection (session fixation), cache poisoning, "
                                "and reflected XSS via response splitting."),
                confidence="confirmed",
                poc=f"curl -si '{test_url}'"))
            log("vuln", f"[high] CRLF injection: {technique} @ {base}")
    return findings

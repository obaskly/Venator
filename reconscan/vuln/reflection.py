"""Reflected-input signal detection (candidate flag, NOT exploitation).

Appends a unique benign canary token to a harmless query parameter and checks
whether it is echoed back unescaped. A hit is a *candidate* for manual XSS
review — the tool never attempts to execute or confirm script execution.
"""
from __future__ import annotations

import secrets
from typing import List
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from ..http import Client
from ..utils import log
from . import Finding

# Inert canary: random alnum, no HTML/JS metacharacters used for the value.
TEST_PARAMS = ["q", "search", "s", "query", "id", "page", "ref"]


def _build(url: str, param: str, token: str) -> str:
    parts = urlparse(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[param] = token
    return urlunparse(parts._replace(query=urlencode(qs)))


def check(client: Client, probe: dict) -> List[Finding]:
    base_url = probe.get("final_url") or probe.get("url")
    findings: List[Finding] = []
    token = "recon" + secrets.token_hex(6)

    for param in TEST_PARAMS:
        test_url = _build(base_url, param, token)
        resp = client.get(test_url, phase="reflection")
        if not resp.ok or resp.status >= 400:
            continue
        if token in resp.text:
            # Look at the immediate context to judge whether it's in raw HTML.
            idx = resp.text.find(token)
            ctx = resp.text[max(0, idx - 30): idx + len(token) + 30]
            ctype = resp.headers.get("content-type", "")
            in_html = "html" in ctype.lower()
            findings.append(Finding(
                title=f"User input reflected in response (param '{param}')",
                severity="info" if not in_html else "low",
                category="reflection", target=base_url,
                evidence=f"Canary '{token}' reflected at {test_url}. Context: …{ctx}… "
                         f"(content-type: {ctype}).",
                recommendation="MANUAL REVIEW: test for XSS by checking output "
                               "encoding/context; verify whether HTML/JS "
                               "metacharacters are escaped. Do not assume "
                               "exploitable without confirmation.",
                confidence="tentative"))
            log("vuln", f"[reflection] param '{param}' reflected at {base_url}")
            break  # one reflected param is enough to flag for manual review

    return findings

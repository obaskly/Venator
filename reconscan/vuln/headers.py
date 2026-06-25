"""Security header analysis (missing / weak / info-leaking) + CSP weakness analysis."""
from __future__ import annotations

import re
from typing import List

from ..data import INFO_LEAK_HEADERS, SECURITY_HEADERS
from ..utils import log
from . import Finding

# CSP directives that are inherently unsafe
_UNSAFE_CSP = {
    "'unsafe-inline'": ("medium", "'unsafe-inline' in CSP allows inline scripts/styles — negates XSS protection"),
    "'unsafe-eval'": ("medium", "'unsafe-eval' in CSP allows eval() — negates XSS protection"),
    "'unsafe-hashes'": ("low", "'unsafe-hashes' weakens CSP integrity"),
}
_WILDCARD_SRC = re.compile(r"\b(script-src|default-src|object-src|style-src)[^;]*\*", re.I)
_DATA_URI = re.compile(r"\b(script-src|default-src)[^;]*data:", re.I)


def _analyse_csp(csp: str, url: str) -> List[Finding]:
    """Inspect an existing CSP header for weaknesses — only flags real bypass vectors."""
    findings: List[Finding] = []
    low = csp.lower()

    for token, (sev, msg) in _UNSAFE_CSP.items():
        if token in low:
            findings.append(Finding(
                title=f"Weak CSP: {token} allows XSS bypass",
                severity=sev, category="headers", target=url,
                evidence=f"Content-Security-Policy contains {token}: {csp[:200]}",
                recommendation=f"Remove {token} from CSP. Use nonces or hashes instead.",
                confidence="firm"))

    if _WILDCARD_SRC.search(csp):
        findings.append(Finding(
            title="Weak CSP: wildcard (*) in script/default-src",
            severity="medium", category="headers", target=url,
            evidence=f"Wildcard source allows any domain to serve scripts: {csp[:200]}",
            recommendation="Pin trusted origins explicitly; remove wildcard sources.",
            confidence="firm"))

    if _DATA_URI.search(csp):
        findings.append(Finding(
            title="Weak CSP: data: URI in script-src enables XSS",
            severity="medium", category="headers", target=url,
            evidence=f"data: URI in script-src allows inline script injection: {csp[:200]}",
            recommendation="Remove data: from script-src/default-src.",
            confidence="firm"))

    # no object-src or default-src
    if "object-src" not in low and "default-src" not in low:
        findings.append(Finding(
            title="Weak CSP: missing object-src (plugin injection possible)",
            severity="low", category="headers", target=url,
            evidence="CSP has no object-src or default-src — Flash/plugin vectors unblocked.",
            recommendation="Add object-src 'none' to block plugin-based injection.",
            confidence="firm"))

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {url}")
    return findings


def check(probe: dict) -> List[Finding]:
    url = probe.get("final_url") or probe.get("url")
    headers = {k.lower(): v for k, v in probe.get("headers", {}).items()}
    findings: List[Finding] = []
    is_https = url.startswith("https://")

    for name, (sev, advice) in SECURITY_HEADERS.items():
        # HSTS only meaningful over HTTPS
        if name == "strict-transport-security" and not is_https:
            continue
        if name not in headers:
            findings.append(Finding(
                title=f"Missing security header: {name}",
                severity=sev, category="headers", target=url,
                evidence=f"Response from {url} has no '{name}' header.",
                recommendation=advice, confidence="firm",
            ))

    # weak HSTS (present but short max-age / no includeSubDomains)
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts)
        max_age = int(m.group(1)) if m else 0
        if max_age < 15552000:  # < 180 days
            findings.append(Finding(
                title="Weak HSTS max-age", severity="low", category="headers",
                target=url,
                evidence=f"Strict-Transport-Security max-age={max_age} (<180d).",
                recommendation="Raise max-age to >=31536000 and add includeSubDomains.",
                confidence="firm",
            ))

    # CSP presence check is already done above (missing = flagged); if PRESENT, analyse it
    csp = headers.get("content-security-policy", "")
    if csp:
        findings += _analyse_csp(csp, url)

    # info-leaking headers
    for h in INFO_LEAK_HEADERS:
        if h in headers and headers[h]:
            val = str(headers[h])
            # only flag when it carries version-ish detail
            if any(ch.isdigit() for ch in val) or h == "x-powered-by":
                findings.append(Finding(
                    title=f"Information disclosure via '{h}' header",
                    severity="info", category="headers", target=url,
                    evidence=f"{h}: {val}",
                    recommendation=f"Suppress or genericize the '{h}' header to "
                                   "avoid leaking stack/version details.",
                    confidence="firm",
                ))

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {url}")
    return findings

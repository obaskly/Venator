"""Security header analysis (missing / weak / info-leaking)."""
from __future__ import annotations

from typing import List

from ..data import INFO_LEAK_HEADERS, SECURITY_HEADERS
from ..utils import log
from . import Finding


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
        import re
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

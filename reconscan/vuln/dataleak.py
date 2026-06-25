"""Sensitive-data exposure detection in HTTP responses.

Scans response bodies for high-confidence leaks: Luhn-valid credit-card numbers,
private-key blocks, and bulk PII (many distinct emails in one response = a likely
user-data dump). Kept high-confidence to avoid the noise generic PII regexes
produce.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..utils import log
from . import Finding

_CC = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PRIVKEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
# obvious non-PII emails to ignore in the bulk heuristic
_EMAIL_NOISE = ("example.com", "email.com", "domain.com", "sentry", "googleapis",
                "schema.org", "w3.org", "test.test", "@2x", "your-email")


def _luhn(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    chk = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        chk += d
    return chk % 10 == 0


def _scan(body: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    if _PRIVKEY.search(body or ""):
        out.append(Finding(
            title="Private key exposed in response", severity="critical",
            category="secret", target=source,
            evidence="a PRIVATE KEY block was returned in the HTTP response.",
            recommendation="Rotate the key immediately; remove from the served content.",
            confidence="firm"))
    cards = [m.group(0) for m in _CC.finditer(body or "") if _luhn(m.group(0))]
    if cards:
        out.append(Finding(
            title="Credit-card number(s) exposed (Luhn-valid)", severity="high",
            category="secret", target=source,
            evidence=f"{len(cards)} Luhn-valid card number(s) in the response "
                     f"(e.g. ****{cards[0][-4:]}).",
            recommendation="Confirm these are live PANs; if so this is a PCI/data-exposure "
                           "report. Mask/remove from responses.",
            confidence="tentative"))
    emails = {e.lower() for e in _EMAIL.findall(body or "")
              if not any(n in e.lower() for n in _EMAIL_NOISE)}
    if len(emails) >= 8:
        out.append(Finding(
            title="Bulk PII exposure — many user emails in one response",
            severity="medium", category="secret", target=source,
            evidence=f"{len(emails)} distinct user emails returned — likely an "
                     "unauthorized user-data listing.",
            recommendation="Verify this endpoint should not enumerate users; add authz/paging.",
            confidence="tentative"))
    return out


def check(probes: List[dict]) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for p in probes:
        if not p.get("final_host_in_scope", True):
            continue
        src = p.get("final_url") or p.get("url")
        for f in _scan(p.get("_body", "") or "", src):
            key = (f.title, src)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    if findings:
        log("vuln", f"sensitive-data exposure: {len(findings)} finding(s)")
    return findings

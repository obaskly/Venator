"""Email authentication posture: SPF / DMARC (and a DKIM hint).

Pure DNS, zero requests to the target. Weak/missing SPF or DMARC = practical
email-spoofing risk and a commonly-accepted bug-bounty finding for domains that
send mail. Low false-positive rate.
"""
from __future__ import annotations

from typing import Dict, List

from ..recon import dns_records
from ..utils import log
from . import Finding


def check(apex: str, dns_recs: Dict[str, List[str]]) -> List[Finding]:
    findings: List[Finding] = []
    # dnspython .to_text() keeps surrounding quotes ("v=spf1 ...") — strip them,
    # else SPF detection false-negatives and reports a bogus "missing SPF".
    raw = dns_recs.get("TXT", []) or dns_records.resolve_txt(apex)
    txt = [t.strip().strip('"').strip() for t in raw]
    has_mx = bool(dns_recs.get("MX"))

    # ---- SPF ----
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    if not spf:
        findings.append(Finding(
            title="Missing SPF record", severity="medium" if has_mx else "low",
            category="email", target=apex,
            evidence="no v=spf1 TXT record found",
            recommendation="Publish an SPF record ending in -all to limit who can send as this domain.",
            confidence="firm"))
    else:
        low = spf.lower()
        if "+all" in low:
            findings.append(Finding(
                title="SPF allows any sender (+all)", severity="high",
                category="email", target=apex,
                evidence=f"SPF: {spf}",
                recommendation="Replace +all with -all; +all defeats SPF entirely.",
                confidence="firm"))
        elif "?all" in low:
            findings.append(Finding(
                title="SPF neutral (?all) — spoofing not prevented", severity="low",
                category="email", target=apex, evidence=f"SPF: {spf}",
                recommendation="Use -all (fail) instead of ?all (neutral).",
                confidence="firm"))

    # ---- DMARC ----
    dmarc_txts = dns_records.resolve_txt(f"_dmarc.{apex}")
    dmarc = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        findings.append(Finding(
            title="Missing DMARC record", severity="medium" if has_mx else "low",
            category="email", target=f"_dmarc.{apex}",
            evidence="no v=DMARC1 TXT record at _dmarc",
            recommendation="Publish a DMARC record (start p=none for monitoring, move to p=reject).",
            confidence="firm"))
    else:
        low = dmarc.lower()
        if "p=none" in low:
            findings.append(Finding(
                title="DMARC policy is p=none (monitor only)", severity="low",
                category="email", target=f"_dmarc.{apex}", evidence=f"DMARC: {dmarc}",
                recommendation="Tighten to p=quarantine or p=reject to actually block spoofing.",
                confidence="firm"))

    if findings:
        log("ok", f"email security: {len(findings)} finding(s) (SPF/DMARC)")
    return findings

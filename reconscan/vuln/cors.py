"""CORS misconfiguration detection.

Sends benign requests with crafted Origin headers and inspects the
Access-Control-Allow-Origin / -Allow-Credentials response. Beyond plain
arbitrary-origin reflection it covers the bypass shapes that actually win
bounties — each carries a UNIQUE attacker canary so a reflected match is
unambiguous (no false positives from a static ACAO):

  * arbitrary external origin reflected            (weak regex / reflect-any)
  * 'null' origin accepted                          (sandboxed iframe / data: URI)
  * arbitrary SUBDOMAIN reflected                   (trusts all subdomains -> chain
                                                     with a subdomain XSS/takeover)
  * prefix-match bug: ``trusted.com.attacker.com``  (startswith() check -> attacker
                                                     fully controls the origin)

Credentials gate severity: an ACAO an attacker controls together with
Allow-Credentials: true means cross-origin theft of authenticated data (high);
without credentials it's a lower-impact misconfiguration. Detection only.
"""
from __future__ import annotations

import secrets
from typing import List
from urllib.parse import urlparse

from ..http import Client
from ..utils import log
from . import Finding


def _probe(client: Client, url: str, origin: str):
    """Send an Origin, return (acao, allow_credentials_bool)."""
    r = client.get(url, phase="cors", extra_headers={"Origin": origin})
    if not r.ok:
        return None, False
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    return acao, acac


def check(client: Client, probe: dict) -> List[Finding]:
    url = probe.get("final_url") or probe.get("url")
    findings: List[Finding] = []
    host = urlparse(url).netloc.split(":")[0]
    rand = secrets.token_hex(3)
    canary = f"evil-rccors-{rand}"

    # (origin, label, base-severity-with-creds, base-severity-without, description)
    shapes = [
        (f"https://{canary}.com", "arbitrary origin", "high", "medium",
         "reflects an arbitrary external origin"),
        (f"https://{canary}.{host}", "subdomain origin", "high", "medium",
         "reflects an arbitrary SUBDOMAIN origin — trusts every subdomain, so an "
         "XSS or subdomain takeover anywhere under the apex yields cross-origin "
         "access to this endpoint"),
        (f"https://{host}.{canary}.com", "prefix-match origin", "high", "medium",
         "accepts an origin that merely STARTS WITH the trusted host — a prefix/"
         f"startswith() validation bug; the attacker fully controls {canary}.com"),
    ]

    arb_acao = arb_acac = None
    for origin, label, sev_creds, sev_plain, desc in shapes:
        acao, acac = _probe(client, url, origin)
        if origin == shapes[0][0]:        # remember arbitrary-origin result for the
            arb_acao, arb_acac = acao, acac   # wildcard check below (no re-request)
        if acao == origin:
            findings.append(Finding(
                title=f"CORS {label} reflected" + (" with credentials" if acac else ""),
                severity=sev_creds if acac else sev_plain, category="cors", target=url,
                evidence=(f"Sent Origin: {origin} -> ACAO: {acao}; Allow-Credentials: "
                          f"{'true' if acac else 'absent'}. The server {desc}."
                          + (" With credentials this enables cross-origin theft of "
                             "authenticated data." if acac else "")),
                recommendation=("Validate Origin against an exact allowlist (full origin "
                                "string, anchored); never reflect it, never use prefix/"
                                "suffix/substring matching, and never pair a reflected "
                                "origin with Allow-Credentials: true."),
                confidence="firm",
                poc=f"curl -s -i -H 'Origin: {origin}' '{url}'"))

    # wildcard ACAO — reuse the arbitrary-origin probe (same Origin) above
    acao0, acac0 = arb_acao, arb_acac
    if acao0 == "*" and acac0:
        findings.append(Finding(
            title="CORS wildcard with credentials", severity="high",
            category="cors", target=url,
            evidence="ACAO: * together with Allow-Credentials: true.",
            recommendation="Disallow '*' when credentials are allowed; pin origins.",
            confidence="firm"))
    elif acao0 == "*":
        findings.append(Finding(
            title="CORS allows any origin (wildcard)", severity="info",
            category="cors", target=url,
            evidence="ACAO: * (no credentials).",
            recommendation="Confirm wildcard is intended for this endpoint.",
            confidence="firm"))

    # null origin acceptance
    nacao, nacac = _probe(client, url, "null")
    if nacao == "null":
        findings.append(Finding(
            title="CORS accepts 'null' origin" + (" with credentials" if nacac else ""),
            severity="high" if nacac else "medium", category="cors", target=url,
            evidence="Origin: null reflected in ACAO" + (" with Allow-Credentials: true"
                     if nacac else "") + " — reachable from a sandboxed iframe / data: URI.",
            recommendation="Reject the 'null' origin.",
            confidence="firm",
            poc=f"curl -s -i -H 'Origin: null' '{url}'"))

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {url}")
    return findings

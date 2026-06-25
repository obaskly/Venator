"""CORS misconfiguration detection.

Sends a benign request with a crafted Origin header and inspects the
Access-Control-Allow-Origin / -Allow-Credentials response. Detection only.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..http import Client
from ..utils import log
from . import Finding


def check(client: Client, probe: dict) -> List[Finding]:
    url = probe.get("final_url") or probe.get("url")
    findings: List[Finding] = []
    host = urlparse(url).netloc

    evil = "https://evil-reconscan-test.example.com"
    resp = client.get(url, phase="cors",
                      extra_headers={"Origin": evil})
    if not resp.ok:
        return findings

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()

    if acao == evil:
        sev = "high" if acac == "true" else "medium"
        findings.append(Finding(
            title="CORS reflects arbitrary Origin",
            severity=sev, category="cors", target=url,
            evidence=f"Sent Origin: {evil} -> ACAO: {acao}; "
                     f"Allow-Credentials: {acac or 'absent'}.",
            recommendation="Whitelist specific trusted origins; never reflect "
                           "the Origin with Allow-Credentials: true.",
            confidence="firm"))
    elif acao == "*" and acac == "true":
        findings.append(Finding(
            title="CORS wildcard with credentials",
            severity="high", category="cors", target=url,
            evidence="ACAO: * together with Allow-Credentials: true.",
            recommendation="Disallow '*' when credentials are allowed; pin origins.",
            confidence="firm"))
    elif acao == "*":
        findings.append(Finding(
            title="CORS allows any origin (wildcard)",
            severity="info", category="cors", target=url,
            evidence="ACAO: * (no credentials).",
            recommendation="Confirm wildcard is intended for this endpoint.",
            confidence="firm"))

    # null origin acceptance
    resp2 = client.get(url, phase="cors", extra_headers={"Origin": "null"})
    if resp2.ok and resp2.headers.get("access-control-allow-origin", "") == "null":
        findings.append(Finding(
            title="CORS accepts 'null' origin",
            severity="medium", category="cors", target=url,
            evidence="Origin: null reflected in ACAO.",
            recommendation="Reject the 'null' origin (sandboxed iframes/data URIs).",
            confidence="firm"))

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {url}")
    return findings

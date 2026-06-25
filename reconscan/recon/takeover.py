"""Subdomain takeover detection (non-destructive).

For each in-scope subdomain we resolve its CNAME chain. If a CNAME points at a
known third-party service AND the live response carries that service's
"unclaimed / no such site" fingerprint, it's a takeover candidate — an attacker
could register the resource and serve content on your subdomain.

Detection only: we never register/claim anything. We just read the CNAME and the
HTTP body and match signatures.
"""
from __future__ import annotations

from typing import List, Optional

from ..config import Config
from ..data import TAKEOVER_SIGNATURES
from ..http import Client
from ..utils import log
from ..external import have, run
from ..vuln import Finding

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # pragma: no cover
    _HAVE_DNS = False

_HAVE_DIG = have("dig")
# Either resolver works; only skip CNAME checks if BOTH are unavailable.
_CAN_RESOLVE = _HAVE_DNS or _HAVE_DIG


def _cname_dnspython(name: str):
    ans = dns.resolver.resolve(name, "CNAME", lifetime=5.0)
    return [str(r.target).rstrip(".").lower() for r in ans]


def _cname_dig(name: str):
    cp = run(["dig", "+short", "CNAME", name], timeout=10)
    if cp.returncode != 0:
        return []
    return [ln.strip().rstrip(".").lower() for ln in cp.stdout.splitlines() if ln.strip()]


def _resolve_cname(host: str) -> List[str]:
    if not _CAN_RESOLVE:
        return []
    chain: List[str] = []
    name = host
    for _ in range(6):  # follow a short chain
        targets: List[str] = []
        try:
            targets = _cname_dnspython(name) if _HAVE_DNS else _cname_dig(name)
        except Exception:
            if _HAVE_DIG:
                try:
                    targets = _cname_dig(name)
                except Exception:
                    targets = []
        if not targets:
            break
        chain.extend(targets)
        name = targets[0]
    return chain


def _match_service(cnames: List[str]):
    for svc, needles, fp, sev in TAKEOVER_SIGNATURES:
        for cn in cnames:
            if any(n in cn for n in needles):
                return svc, fp, sev, cn
    return None


def check_host(client: Client, host: str) -> Optional[Finding]:
    cnames = _resolve_cname(host)
    if not cnames:
        return None
    match = _match_service(cnames)
    if not match:
        return None
    svc, fp, sev, cn = match

    # confirm the dangling fingerprint in the live body
    body = ""
    for scheme in ("https", "http"):
        resp = client.get(f"{scheme}://{host}", phase="takeover")
        if resp.ok or resp.text:
            body = resp.text
            if body:
                break
    if fp.lower() not in body.lower():
        # CNAME points at the service but it's still claimed → not a takeover
        return None

    return Finding(
        title=f"Possible subdomain takeover ({svc})",
        severity=sev, category="takeover", target=host,
        evidence=f"CNAME -> {cn} ; body matches '{fp}' (service unclaimed)",
        recommendation=("Verify the third-party resource is truly unclaimed, then "
                        "either reclaim/point it correctly or remove the dangling "
                        "DNS record. Do NOT register the resource on the program's "
                        "behalf — document and report."),
        confidence="firm")


def scan(client: Client, hosts: List[str], cfg: Config) -> List[Finding]:
    if not _CAN_RESOLVE:
        log("warn", "takeover: no CNAME resolver (install dnspython or dig), skipping")
        return []
    log("step", f"Subdomain takeover checks ({len(hosts)} hosts)")
    findings: List[Finding] = []
    for h in hosts:
        f = check_host(client, h)
        if f:
            findings.append(f)
            log("vuln", f"[{f.severity}] {f.title} @ {f.target}")
    log("ok", f"takeover: {len(findings)} candidate(s)")
    return findings

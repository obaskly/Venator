"""DNS record gathering (A/AAAA/MX/TXT/NS/CNAME/SOA).

Uses dnspython if available; otherwise falls back to the `dig` binary.
"""
from __future__ import annotations

from typing import Dict, List

from ..audit import AuditLog
from ..external import have, run
from ..utils import log

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

try:
    import dns.resolver  # type: ignore
    _HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    _HAVE_DNSPYTHON = False


def _via_dnspython(name: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    for rtype in RECORD_TYPES:
        try:
            ans = resolver.resolve(name, rtype)
            out[rtype] = sorted(r.to_text() for r in ans)
        except Exception:
            continue
    return out


def _via_dig(name: str, audit: AuditLog) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for rtype in RECORD_TYPES:
        cp = run(["dig", "+short", name, rtype], timeout=15, audit=audit, phase="dns")
        vals = [l.strip() for l in cp.stdout.splitlines() if l.strip()]
        if vals:
            out[rtype] = sorted(vals)
    return out


def gather(name: str, audit: AuditLog) -> Dict[str, List[str]]:
    log("step", f"DNS records for {name}")
    if _HAVE_DNSPYTHON:
        # record one audit entry to note the lookup occurred
        audit.record("DNS", f"resolve://{name}", phase="dns", note="dnspython lookups")
        records = _via_dnspython(name)
    elif have("dig"):
        records = _via_dig(name, audit)
    else:
        log("warn", "no dnspython and no dig — skipping DNS records")
        return {}
    for rtype, vals in records.items():
        for v in vals:
            log("ok", f"{rtype:6} {v}")
    return records


def resolve_txt(name: str) -> List[str]:
    """TXT records for a name (used for DMARC/SPF checks). Empty on failure."""
    if _HAVE_DNSPYTHON:
        try:
            ans = dns.resolver.resolve(name, "TXT", lifetime=5.0)
            return [r.to_text().strip('"') for r in ans]
        except Exception:
            return []
    if have("dig"):
        cp = run(["dig", "+short", "TXT", name], timeout=10)
        return [l.strip().strip('"') for l in cp.stdout.splitlines() if l.strip()]
    return []


def resolve_a(name: str) -> List[str]:
    """Return A/AAAA addresses for a host (used by subdomain liveness check)."""
    if _HAVE_DNSPYTHON:
        addrs: List[str] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 3.0
        for rtype in ("A", "AAAA"):
            try:
                ans = resolver.resolve(name, rtype)
                addrs.extend(r.to_text() for r in ans)
            except Exception:
                continue
        return addrs
    if have("dig"):
        cp = run(["dig", "+short", name, "A"], timeout=8)
        return [l.strip() for l in cp.stdout.splitlines()
                if l.strip() and not l.endswith(".")]
    return []

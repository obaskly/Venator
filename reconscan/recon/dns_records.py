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


def resolve_ns(name: str) -> List[str]:
    """Authoritative name servers for a zone (used to target AXFR attempts)."""
    if _HAVE_DNSPYTHON:
        try:
            ans = dns.resolver.resolve(name, "NS", lifetime=5.0)
            return [r.to_text().rstrip(".").lower() for r in ans]
        except Exception:
            return []
    if have("dig"):
        cp = run(["dig", "+short", "NS", name], timeout=10)
        return [l.strip().rstrip(".").lower()
                for l in cp.stdout.splitlines() if l.strip()]
    return []


# Common SRV service records — service discovery often exposes hosts that no
# subdomain brute will surface (mail/VoIP/AD/collab infra).
_SRV_NAMES = [
    "_sip._tcp", "_sips._tcp", "_sip._udp", "_ldap._tcp", "_kerberos._tcp",
    "_kerberos._udp", "_kpasswd._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_autodiscover._tcp", "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp",
    "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_submission._tcp", "_smtp._tcp",
    "_sipfederationtls._tcp", "_h323cs._tcp", "_vlmcs._tcp", "_minecraft._tcp",
]


def enum_srv(apex: str, audit: AuditLog) -> tuple:
    """Query common SRV records. Returns (records_dict, target_hostnames_set)."""
    records: Dict[str, List[str]] = {}
    targets: set = set()
    if _HAVE_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        for name in _SRV_NAMES:
            fq = f"{name}.{apex}"
            try:
                ans = resolver.resolve(fq, "SRV")
            except Exception:
                continue
            vals = []
            for r in ans:
                vals.append(r.to_text())
                tgt = str(r.target).rstrip(".").lower()
                if tgt and tgt != ".":
                    targets.add(tgt)
            if vals:
                records[fq] = sorted(vals)
    elif have("dig"):
        for name in _SRV_NAMES:
            fq = f"{name}.{apex}"
            cp = run(["dig", "+short", "SRV", fq], timeout=8, audit=audit, phase="dns")
            vals = [l.strip() for l in cp.stdout.splitlines() if l.strip()]
            if vals:
                records[fq] = sorted(vals)
                for v in vals:
                    parts = v.split()
                    if parts:
                        tgt = parts[-1].rstrip(".").lower()
                        if tgt and tgt != ".":
                            targets.add(tgt)
    if records:
        audit.record("DNS", f"srv://{apex}", phase="dns", note="SRV enumeration")
        log("ok", f"SRV: {len(records)} service record(s), {len(targets)} target host(s)")
    return records, targets


def _axfr_finding(apex: str, ns: str, n: int):
    from ..vuln import Finding
    return Finding(
        title="DNS zone transfer (AXFR) allowed",
        severity="high", category="misconfig", target=apex,
        evidence=(f"Authoritative name server `{ns}` answered a full AXFR zone "
                  f"transfer for `{apex}` ({n} records). The entire DNS zone — "
                  f"every subdomain, frequently internal-only hosts — is disclosed."),
        recommendation=("Restrict zone transfers to authorized secondaries only "
                        "(allow-transfer ACL / TSIG). Treat every disclosed name as "
                        "in-scope recon."),
        confidence="confirmed",
        poc=f"dig AXFR {apex} @{ns}")


def try_axfr(apex: str, ns_hosts: List[str], audit: AuditLog) -> tuple:
    """Attempt an AXFR zone transfer against each authoritative NS (read-only).
    Returns (discovered_names_set, [Finding])."""
    names: set = set()
    findings: list = []
    if _HAVE_DNSPYTHON:
        import dns.query
        import dns.zone
        for ns in ns_hosts:
            ns_addrs = resolve_a(ns) or [ns]
            for ip in ns_addrs:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ip, apex, lifetime=20.0))
                except Exception:
                    continue
                audit.record("DNS", f"axfr://{apex}@{ns}", phase="dns",
                             note="AXFR attempt")
                got = set()
                for node in z.nodes.keys():
                    fq = str(node)
                    if fq == "@":
                        fq = apex
                    elif not fq.endswith("."):
                        fq = f"{fq}.{apex}"
                    fq = fq.rstrip(".").lower()
                    if fq.endswith(apex):
                        got.add(fq)
                if got:
                    names |= got
                    findings.append(_axfr_finding(apex, ns, len(got)))
                    log("vuln", f"AXFR allowed by {ns} ({len(got)} names)")
                    break   # one successful transfer per NS is enough
    elif have("dig"):
        for ns in ns_hosts:
            cp = run(["dig", "AXFR", apex, f"@{ns}"], timeout=25, audit=audit, phase="dns")
            out = cp.stdout
            recs = [l for l in out.splitlines() if l and not l.startswith(";")]
            low = out.lower()
            if len(recs) > 2 and "failed" not in low and "timed out" not in low:
                for l in recs:
                    parts = l.split()
                    if parts:
                        nm = parts[0].rstrip(".").lower()
                        if nm.endswith(apex):
                            names.add(nm)
                findings.append(_axfr_finding(apex, ns, len(recs)))
                log("vuln", f"AXFR allowed by {ns}")
    return names, findings


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

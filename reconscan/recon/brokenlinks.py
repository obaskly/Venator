"""Broken-link hijacking detection (DNS-only, non-destructive).

Pages routinely reference third-party assets (scripts, links, images) on hosts
whose domain has since lapsed. If the registrable domain is unregistered, an
attacker can claim it and serve content into the victim page (stored-XSS /
phishing / supply-chain). This finds such *claimable* external references.

Strictly DNS-only and read-only: it fetches already-in-scope pages through the
scope-gated client, extracts external hostnames, and asks DNS whether the
registrable domain still exists. It NEVER sends HTTP to an out-of-scope host and
NEVER registers anything.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse

from ..config import Config
from ..utils import Scope, log
from ..vuln import Finding
from . import dns_records

_ATTR_RE = re.compile(r"""(?:href|src|action|data-src)\s*=\s*['"]([^'"]+)['"]""", re.I)
_ABS_RE = re.compile(r"https?://[^\s'\"<>)\\]+", re.I)

# a syntactically valid DNS hostname: labels of [a-z0-9-], ≥2 labels, real-ish TLD.
# Guards against extraction artifacts (trailing backslash/quote/comma, JS regex
# fragments) being treated as a "claimable" domain — those produce NXDOMAIN and
# would otherwise flag the site's OWN domain as unregistered.
_VALID_HOST = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")

# well-known infra whose absence is never a real takeover lead (standards bodies,
# doc namespaces, RFC examples, loopback)
_IGNORE_SUFFIX = ("w3.org", "schema.org", "example.com", "example.org",
                  "example.net", "localhost", "googleapis.com", "gstatic.com")

# common multi-label public suffixes for a crude eTLD+1
_MULTI_SUFFIX = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au",
                 "co.jp", "co.nz", "com.br", "co.in", "co.za", "com.mx"}


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = ".".join(parts[-2:])
    if two in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return two


def _domain_exists(domain: str) -> bool:
    """True if the registrable domain is registered/delegated (has SOA or NS).

    Conservative: anything inconclusive returns True so we never emit a false
    'unregistered' claim."""
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return bool(dns_records.resolve_a(domain))  # weaker fallback
    nxdomain = 0
    for rt in ("SOA", "NS"):
        try:
            dns.resolver.resolve(domain, rt, lifetime=5.0)
            return True
        except dns.resolver.NoAnswer:
            return True            # exists, just no record of that type
        except dns.resolver.NXDOMAIN:
            nxdomain += 1
        except dns.resolver.NoNameservers:
            return True
        except Exception:
            continue
    return nxdomain == 0           # only "unregistered" if every query said NXDOMAIN


def check(client, service_bases: List[str], scope: Scope, cfg: Config,
          audit, max_pages: int = 20) -> List[Finding]:
    log("step", "Broken-link hijack scan (DNS-only, non-destructive)")
    findings: List[Finding] = []
    ext_refs: Dict[str, str] = {}   # external host -> example source page

    for base in service_bases[:max_pages]:
        r = client.get(base, phase="brokenlinks")
        if not r.ok or not r.text:
            continue
        cands = set(_ATTR_RE.findall(r.text)) | set(_ABS_RE.findall(r.text))
        for c in cands:
            if c.startswith("//"):
                c = "https:" + c
            if not c.lower().startswith("http"):
                continue
            h = (urlparse(c).hostname or "").lower().rstrip(".")
            if not h or scope.host_in_scope(h):
                continue
            if not _VALID_HOST.match(h):
                continue   # extraction artifact, not a real hostname
            if any(h == s or h.endswith("." + s) for s in _IGNORE_SUFFIX):
                continue
            ext_refs.setdefault(h, base)

    if not ext_refs:
        log("ok", "no external references found")
        return findings
    log("info", f"{len(ext_refs)} external host(s) referenced — checking DNS")

    checked: Dict[str, bool] = {}
    for host, src in sorted(ext_refs.items()):
        dom = _registrable(host)
        if dom not in checked:
            checked[dom] = _domain_exists(dom)
            audit.record("DNS", f"resolve://{dom}", phase="brokenlinks",
                         note="brokenlink-soa-check")
        if checked[dom]:
            continue
        findings.append(Finding(
            title="Broken-link hijack: reference to UNREGISTERED domain",
            severity="medium", category="takeover", target=src,
            evidence=(f"Page references an external asset on `{host}`, but the "
                      f"registrable domain `{dom}` returns NXDOMAIN (no SOA/NS) — "
                      f"it appears unregistered and therefore claimable."),
            recommendation=("Report the dangling reference (claiming the domain is "
                            "out of scope). An attacker registering "
                            f"`{dom}` could serve content into this page "
                            "(stored-XSS / phishing / supply chain). Remove or "
                            "repoint the reference."),
            confidence="firm",
            poc=f"dig SOA {dom}   # NXDOMAIN -> domain is free to register"))
        log("vuln", f"broken-link hijack: {host} (domain {dom} unregistered) on {src}")

    if not findings:
        log("ok", "no claimable broken links found")
    return findings

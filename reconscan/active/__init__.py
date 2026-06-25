"""Active probing phase — lead generation, NOT weaponized exploitation.

This phase sends crafted-but-benign inputs to in-scope targets and looks for a
*signal* that a vulnerability class is present (an SQL error string, a reflected
raw `<`, a rendered `49`, a 200 where a 403 was expected, an external redirect).
Every signal is a LEAD for manual confirmation — the tool never weaponizes,
never modifies/deletes/exfiltrates data, sends no blind/time-based payloads (no
DB load), and runs no commands.

All requests stay rate-limited, scope-gated, and audited like the rest of the
tool. Authorized targets only.
"""
from __future__ import annotations

from typing import List

from ..config import Config
from ..http import Client
from ..utils import Scope, log
from ..vuln import Finding
from . import bypass, redirect, injection, crlf, oauth


def run_active(client: Client, scope: Scope, services: List[dict],
               endpoints: List[dict], cfg: Config) -> List[Finding]:
    log("step", "Active probing (lead generation — benign, non-destructive)")
    findings: List[Finding] = []

    # candidate URLs: service base + discovered endpoints (in-scope only)
    base_urls = [s["base_url"] for s in services]
    discovered = _gather_discovered(services, endpoints, scope)

    findings += bypass.check(client, base_urls, discovered, cfg)
    findings += redirect.check(client, base_urls, cfg)
    findings += crlf.check(client, base_urls, cfg)
    findings += injection.check(client, base_urls, discovered, cfg)
    findings += oauth.check(client, base_urls, endpoints, cfg, scope)

    log("ok", f"active probing: {len(findings)} lead(s)")
    return findings


def _gather_discovered(services, endpoints, scope, cap: int = 60) -> List[dict]:
    """Build a list of {url, status} for endpoints we found, in scope.
    Pulls dir-brute hits, robots paths, and sitemap URLs."""
    from urllib.parse import urljoin
    seen = set()
    out = []
    default_base = services[0]["base_url"] if services else None

    def add(url, status=None):
        if url and url not in seen and scope.url_in_scope(url):
            seen.add(url)
            out.append({"url": url, "status": status})

    for ep in endpoints:
        base = ep.get("base_url") or default_base
        for d in ep.get("discovered", []):
            if isinstance(d, dict):
                add(d.get("url"), d.get("status"))
        for p in ep.get("robots", []):
            if base and p.startswith("/"):
                add(urljoin(base, p))
        for loc in ep.get("sitemap", []):
            add(loc)
    return out[:cap]

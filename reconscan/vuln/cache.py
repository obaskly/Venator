"""Web cache poisoning + host-header injection — with cache-persistence CONFIRMATION.

Unkeyed request headers (X-Forwarded-Host, X-Host, X-Original-URL, …) carry a unique
canary. If the canary is reflected into the response we have host-header injection; if
the response is then served *from cache to a request that did NOT send the header*, the
header is unkeyed and the cache is poisonable — a confirmed web cache poisoning.

Confirmation (the part that turns a guess into proof, near-zero FP):
  1. pick a fresh per-attempt cache-buster key `?cb=<rand>` (so we ONLY ever touch our
     own throwaway key — never a shared/production cache entry: this is the safety core),
  2. request it ONCE with the unkeyed header + canary → poisoned response gets cached,
  3. re-request the SAME `cb` key WITHOUT the header → if the canary is still there, the
     second request provably never sent it, so its presence can only come from the cache:
     unkeyed + cached = CONFIRMED poisoning. X-Cache miss→hit / Age corroborates.
Reflected-but-not-cached stays a (tentative) host-header-injection lead, as before.

Severity follows the SINK: canary in a redirect Location or a resource/script URL
(`src=`, `href=`, `//canary`) = high (victims get attacker host); body-text only = medium.

Ref: https://portswigger.net/web-security/web-cache-poisoning
"""
from __future__ import annotations

import re
import secrets
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..http import Client
from ..utils import log
from . import Finding

# (header, value-template{C}) — {C} replaced with the canary host. Every vector
# carries the canary so reflection is provable; non-canary scheme/proto downgrades
# are handled by other modules (redirect/oauth), not here.
_UNKEYED = [
    ("X-Forwarded-Host", "{C}"),
    ("X-Forwarded-Server", "{C}"),
    ("X-Host", "{C}"),
    ("X-HTTP-Host-Override", "{C}"),
    ("Forwarded", "host={C}"),
    ("X-Original-URL", "/{C}"),
    ("X-Rewrite-URL", "/{C}"),
]
_CACHE_HINTS = ("cf-cache-status", "x-cache", "x-cache-hits", "age",
                "x-served-by", "x-vercel-cache", "x-nextjs-cache", "x-drupal-cache")


def _cachebust(url: str) -> str:
    pr = urlparse(url)
    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
    qs["cb"] = secrets.token_hex(6)
    return urlunparse(pr._replace(query=urlencode(qs)))


def _cacheable(headers: dict) -> bool:
    cc = headers.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc or ("max-age" in cc and "max-age=0" not in cc):
        return True
    return any(h in headers for h in _CACHE_HINTS)


def _cache_state(headers: dict) -> str:
    for h in ("cf-cache-status", "x-cache", "x-vercel-cache", "x-nextjs-cache"):
        if h in headers:
            return f"{h}={headers[h]}"
    if "age" in headers:
        return f"age={headers['age']}"
    return "no cache header"


def _sink(canary: str, body: str, loc: str) -> Tuple[str, str]:
    """Return (where, impact) — impact 'high' if canary lands in an active URL sink."""
    if canary in loc:
        return ("Location header", "high")
    # canary used as a host/URL in an executable/resource context
    rx = re.compile(r"""(?:src|href|action|formaction|data-[\w-]+)\s*=\s*['"]?\s*"""
                    r"""(?:https?:)?//""" + re.escape(canary), re.I)
    if rx.search(body) or ("//" + canary) in body or ("://" + canary) in body:
        return ("resource/script URL in body", "high")
    if canary in body:
        return ("body text", "medium")
    return ("", "")


def _attempt(client: Client, base: str, header: str, value_tmpl: str
             ) -> Optional[dict]:
    canary = f"rcp{secrets.token_hex(4)}.example.com"
    value = value_tmpl.replace("{C}", canary)
    key = _cachebust(base)   # fresh throwaway key — only WE ever hit it
    # 1) poison: request the key once WITH the unkeyed header
    r = client.get(key, phase="active", allow_redirects=False,
                   extra_headers={header: value})
    if not (r and r.ok):
        return None
    where, impact = _sink(canary, r.text or "", r.headers.get("location", ""))
    if not where:
        return None  # not reflected at all
    # 2) confirm: re-request the SAME key WITHOUT the header
    conf = client.get(key, phase="active", allow_redirects=False)
    persisted = bool(conf and (canary in (conf.text or "")
                               or canary in conf.headers.get("location", "")))
    return {
        "header": header, "value": value, "canary": canary, "where": where,
        "impact": impact, "cacheable": _cacheable(r.headers),
        "persisted": persisted, "key": key,
        "state1": _cache_state(r.headers),
        "state2": _cache_state(conf.headers) if conf else "n/a",
    }


def check(client: Client, base_urls: List[str]) -> List[Finding]:
    if not base_urls:
        return []
    log("info", f"cache-poisoning / host-header probe on {len(base_urls)} base URL(s)")
    findings: List[Finding] = []

    for base in base_urls:
        if client.over_budget():
            break
        best: Optional[dict] = None
        for header, tmpl in _UNKEYED:
            res = _attempt(client, base, header, tmpl)
            if not res:
                continue
            if res["persisted"]:
                best = res
                break  # confirmed — stop probing this base
            # keep the first reflecting (unconfirmed) vector as a fallback lead
            if best is None:
                best = res
        if not best:
            continue

        h, v, where = best["header"], best["value"], best["where"]
        if best["persisted"]:
            sev = best["impact"]  # high if active sink, else medium — but it's CONFIRMED
            findings.append(Finding(
                title=f"Web cache poisoning confirmed via {h}",
                severity=sev, category="cache", target=base,
                evidence=(
                    f"Unkeyed '{h}: {v}' was reflected into the {where}, then the SAME "
                    f"cache-buster key returned the injected canary on a follow-up request "
                    f"that did NOT send the header — proof the response was cached and the "
                    f"header is unkeyed. Cache state: req1 {best['state1']} → req2 "
                    f"{best['state2']}. Tested only on a throwaway ?cb= key (no shared "
                    f"cache touched). EXPLOITED (poisoned our own cache entry as proof)."),
                recommendation=(
                    f"Add '{h}' to the cache Vary key or stop reflecting it into responses; "
                    f"validate Host and never build URLs from X-Forwarded-* / Forwarded. "
                    f"Confirm victim impact within the program's rules before reporting."),
                confidence="confirmed",
                poc=f"curl -s '{best['key']}' -H '{h}: {v}'   # then re-request without the header"))
            log("vuln", f"[{sev}] cache poisoning CONFIRMED: {h} @ {base}")
        elif best["cacheable"]:
            findings.append(Finding(
                title=f"Web cache poisoning candidate via {h}",
                severity="medium", category="cache", target=base,
                evidence=(f"unkeyed '{h}: {v}' reflected in {where}; response appears "
                          f"cacheable ({best['state1']}) but the canary did not persist on "
                          f"the follow-up (cache may key the header or need warm-up)."),
                recommendation=("Re-test (some caches need N requests to warm); if it "
                                "persists this is poisoning. Add the header to Vary or "
                                "stop reflecting it."),
                confidence="tentative"))
            log("vuln", f"[medium] cache poisoning candidate: {h} @ {base}")
        else:
            findings.append(Finding(
                title=f"Host-header injection via {h}",
                severity="medium", category="cache", target=base,
                evidence=f"unkeyed '{h}: {v}' reflected in {where} (no cache observed).",
                recommendation=("Check for password-reset poisoning / open-redirect / SSRF "
                                "impact. Validate Host; stop trusting X-Forwarded-* for URLs."),
                confidence="tentative"))
            log("vuln", f"[medium] host-header injection: {h} @ {base}")
    return findings

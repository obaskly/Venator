"""Web Cache Deception (WCD) detection — authenticated-content leak via path
confusion (non-destructive, requires an authenticated session).

Classic WCD: a dynamic, per-user page (e.g. /account) is requested as
/account/nonexistent.css. The origin ignores the bogus suffix and serves the
private page, but a caching layer in front sees a ".css" path and caches the
response as a static asset under a key any anonymous user can hit — leaking the
victim's private data.

Confirmation here is differential and near-zero-FP:
  1. prove the base path is PRIVATE: authenticated GET = 2xx w/ body, while an
     ANONYMOUS GET of the same path is denied (401/403/redirect/different body);
  2. prove path confusion: authed GET of <path><static-suffix> still returns the
     private body;
  3. prove the LEAK: an ANONYMOUS GET of that same suffixed URL (sent right after
     the authed one primed any cache) returns the private body — i.e. a cache
     served authenticated content to an unauthenticated client.

Only step 3 firing produces a finding, and it carries an identity marker that is
present in the authenticated body but absent from the anonymous-denied body.

Ref: https://portswigger.net/web-security/web-cache-deception
"""
from __future__ import annotations

import dataclasses
import re
import secrets
from typing import List, Optional
from urllib.parse import urlparse

from ..config import Config
from ..http import Client
from ..utils import Scope, dedup_keep_order, log
from . import Finding

# sensitive, typically per-user routes worth probing for WCD
_SEED_PATHS = ["/account", "/profile", "/api/me", "/me", "/user", "/api/user",
               "/dashboard", "/settings", "/api/account", "/api/profile",
               "/identity/api/v2/user/dashboard", "/api/v2/user/dashboard"]

# static-looking suffixes that should not change origin routing but may change
# the CACHE key. {R} = random token so we never reuse a real static asset name.
_SUFFIXES = ["/{R}.css", "/{R}.js", ";{R}.css", "%2f{R}.css", ".css", "/{R}.jpg"]

_TOKEN_RE = re.compile(r"[A-Za-z0-9_@.\-]{8,40}")


def _has_auth(cfg: Config) -> bool:
    return bool(getattr(cfg, "auth_bearer", "") or getattr(cfg, "auth_cookie", "")
                or getattr(cfg, "auth_headers", []))


def _anon_client(cfg: Config, scope: Scope, audit) -> Client:
    """A second client with NO credentials (no bearer/cookie/headers) so we can
    replay a request as an anonymous visitor."""
    bare = dataclasses.replace(cfg, auth_bearer="", auth_cookie="", auth_headers=[])
    return Client(bare, scope, audit)


def _markers(authed: str, denied: str) -> List[str]:
    """Tokens that appear in the authenticated body but NOT in the anonymous
    denied body — strong evidence a later response is the private page."""
    a = set(_TOKEN_RE.findall(authed or ""))
    d = set(_TOKEN_RE.findall(denied or ""))
    out = [t for t in a - d if not t.isdigit()]
    # prefer longer / identity-ish tokens (emails, names, csrf-looking)
    out.sort(key=lambda t: ("@" in t, len(t)), reverse=True)
    return out[:8]


def _private(authed_resp, anon_resp) -> bool:
    """Base path is genuinely private: authed 2xx-with-body, anon denied/different."""
    if not (authed_resp.ok and 200 <= authed_resp.status < 300):
        return False
    if len(authed_resp.text or "") < 16:
        return False
    if not anon_resp.ok:
        return True  # anon transport-blocked counts as denied
    if anon_resp.status in (401, 403) or anon_resp.status in (301, 302, 303, 307, 308):
        return True
    # anon got 2xx too — only "private" if the body is materially different
    return anon_resp.text != authed_resp.text


def _candidate_paths(base: str, discovered: List[dict]) -> List[str]:
    host = urlparse(base).netloc
    paths = list(_SEED_PATHS)
    for d in discovered or []:
        if not isinstance(d, dict):
            continue
        u = d.get("url", "")
        if urlparse(u).netloc == host and d.get("status") in (200, 401, 403):
            p = urlparse(u).path
            if p and p != "/":
                paths.append(p)
    return dedup_keep_order(paths)[:8]


def check(client: Client, base_urls: List[str], discovered: List[dict],
          cfg: Config, scope: Scope, audit) -> List[Finding]:
    if not base_urls or not _has_auth(cfg):
        return []
    log("info", f"web cache deception probe on {len(base_urls)} base URL(s) (authed)")
    findings: List[Finding] = []
    anon = _anon_client(cfg, scope, audit)

    for base in base_urls:
        root = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
        for path in _candidate_paths(base, discovered):
            if cfg.max_requests and client.over_budget():
                return findings
            url = root + path
            a = client.get(url, phase="vuln", allow_redirects=False)
            n = anon.get(url, phase="vuln", allow_redirects=False)
            if not _private(a, n):
                continue
            markers = _markers(a.text, n.text or "")
            if not markers:
                continue

            hit = None
            for suf in _SUFFIXES:
                rnd = secrets.token_hex(4)
                test = url + suf.replace("{R}", rnd)
                # 1) authed: does origin still serve the private page on a .css URL?
                ta = client.get(test, phase="vuln", allow_redirects=False)
                if not (ta.ok and 200 <= ta.status < 300):
                    continue
                if not any(m in (ta.text or "") for m in markers):
                    continue  # suffix changed routing (got a real asset/404) — skip
                # 2) anon: replay the SAME url; if a cache serves the private body…
                tn = anon.get(test, phase="vuln", allow_redirects=False)
                if tn.ok and 200 <= tn.status < 300 and \
                        any(m in (tn.text or "") for m in markers):
                    leaked = [m for m in markers if m in (tn.text or "")][:3]
                    hit = (test, suf, leaked, tn.headers.get("x-cache")
                           or tn.headers.get("cache-control", "-"))
                    break

            if hit:
                test, suf, leaked, cache_hdr = hit
                findings.append(Finding(
                    title="Web cache deception — authenticated content cached for anon access",
                    severity="high", category="cache", target=test,
                    evidence=(f"private page {url} served to an ANONYMOUS request at "
                              f"{test} (suffix '{suf}'); leaked identity marker(s): "
                              f"{', '.join(leaked)} (cache: {cache_hdr})."),
                    recommendation=("Don't cache responses for authenticated routes; key the "
                                    "cache on auth and set Cache-Control: private/no-store. "
                                    "Make the origin reject or 404 unknown static suffixes "
                                    "instead of serving the dynamic page."),
                    confidence="confirmed",
                    poc=f"# authed primes, anon reads:\ncurl -si '{test}'"))
                log("vuln", f"[high] web cache deception: {url} leaked via {suf}")
                break  # one confirmed WCD per base is enough
    return findings

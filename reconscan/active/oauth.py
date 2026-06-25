"""OAuth 2.0 / OIDC weakness probing — redirect_uri validation + flow hygiene.

The crown-jewel OAuth bug is a weak `redirect_uri` validator: if the authorization
server will send the authorization code (or token) to a URI the attacker controls,
that is a one-click account takeover. We confirm it with an ERROR-DIFFERENTIAL
oracle that works pre-authentication:

  1. baseline  — the app's REAL redirect_uri must be accepted (sanity),
  2. control   — a totally-unrelated host MUST be rejected by a sane validator,
  3. bypass    — classic confusion shapes (subdomain-suffix, path-embed, userinfo
                 `@`) that smuggle the SAME unique attacker host past the check.

A finding is emitted only when the attacker host is BOTH not-rejected AND
reflected back by the server (it carried our value forward) — so a server that
ignores redirect_uri, or rejects everything, produces nothing. Benign throughout:
we never complete a flow, capture a code, or follow the off-scope redirect (the
Client refuses that); we only read the server's accept/reject decision.

Also surfaces the OIDC discovery document and a missing-`state` (CSRF) signal.
"""
from __future__ import annotations

import json
import random
import re
import string
from typing import Dict, List
from urllib.parse import (urljoin, urlparse, urlencode, parse_qs, parse_qsl,
                          urlunparse)

from ..config import Config
from ..http import Client
from ..utils import Scope, dedup_keep_order, log
from ..vuln import Finding

_AUTHZ_PATH = re.compile(r"(?:/oauth2?/authorize|/authorize|/connect/authorize|"
                         r"/o/oauth2/[^/]*auth|openid-connect/auth|/auth/realms/)", re.I)
_REJECT = re.compile(
    r"(?:redirect[_ ]?uri[^a-z]{0,40}(?:mismatch|invalid|not[_ ]?(?:match|registered|"
    r"allowed|valid|whitelisted)|unregistered|untrusted))|error=invalid_request|"
    r"error=redirect_uri_mismatch|error=unauthorized_client|invalid[_ ]?redirect",
    re.I)
_STATE_REQUIRED = re.compile(r"state[^a-z]{0,20}(?:required|missing|invalid)", re.I)

_WELLKNOWN = ["/.well-known/openid-configuration",
              "/.well-known/oauth-authorization-server"]


def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _set_redirect(url: str, new_redirect: str) -> str:
    pr = urlparse(url)
    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
    qs["redirect_uri"] = new_redirect
    if "state" not in qs:
        qs["state"] = "rc" + _rand(6)
    return urlunparse(pr._replace(query=urlencode(qs, safe=":/@?&=%.")))


def _drop_state(url: str) -> str:
    pr = urlparse(url)
    qs = [(k, v) for k, v in parse_qsl(pr.query, keep_blank_values=True)
          if k.lower() != "state"]
    return urlunparse(pr._replace(query=urlencode(qs, safe=":/@?&=%.")))


def _rejected(resp) -> bool:
    if not resp.ok:
        return True
    if resp.status in (400, 401, 403):
        # a 4xx that names redirect_uri is a rejection; a bare 401/403 login wall
        # is NOT (the validator may run after auth) — be conservative.
        if _REJECT.search(resp.text or "") or "redirect" in resp.headers.get("location", "").lower():
            return True
        if resp.status == 400:
            return True
    blob = (resp.headers.get("location", "") + " " + (resp.text or "")[:4000])
    return bool(_REJECT.search(blob))


def _reflects(resp, needle: str) -> bool:
    """True only when the server actually SENDS the browser to the attacker host —
    a 30x Location, a form_post action, a JS redirect, or a meta-refresh. A stray
    echo (e.g. redirect_uri sitting in a login form's hidden input) does NOT count;
    that's a common false-positive source since the value may still be validated
    after authentication."""
    if needle in resp.headers.get("location", ""):
        return True
    body = (resp.text or "")[:20000]
    esc = re.escape(needle)
    sinks = (
        rf'action\s*=\s*["\']https?://[^"\']*{esc}',                  # form_post mode
        rf'location\.(?:href|replace|assign)\s*[=(]\s*["\']?https?://[^"\']*{esc}',
        rf'url=\s*["\']?https?://[^"\'>\s]*{esc}',                    # meta refresh
        rf'window\.location\s*=\s*["\']https?://[^"\']*{esc}',
    )
    return any(re.search(p, body, re.I) for p in sinks)


def _harvest_authorize(base_urls: List[str], endpoints: List[dict],
                       scope: Scope) -> List[str]:
    """Live authorize URLs that already carry client_id + redirect_uri (real
    values) — the only ones we can differentially test pre-auth."""
    cands: List[str] = []
    pool: List[str] = []
    for ep in endpoints:
        for d in ep.get("discovered", []):
            if isinstance(d, dict) and d.get("url"):
                pool.append(d["url"])
        pool += [u for u in ep.get("sitemap", []) if u]
    for u in pool:
        if not scope.url_in_scope(u):
            continue
        pr = urlparse(u)
        if not _AUTHZ_PATH.search(pr.path):
            continue
        qs = parse_qs(pr.query)
        if "client_id" in qs and "redirect_uri" in qs:
            cands.append(u)
    return dedup_keep_order(cands)[:5]


def _discovery(client: Client, base_urls: List[str], scope: Scope) -> List[Finding]:
    out: List[Finding] = []
    seen_docs = set()
    for base in base_urls:
        for wk in _WELLKNOWN:
            r = client.get(urljoin(base, wk), phase="active", allow_redirects=False)
            if not r.ok or r.status != 200:
                continue
            try:
                doc = json.loads(r.text)
            except Exception:
                continue
            if not isinstance(doc, dict) or "authorization_endpoint" not in doc:
                continue
            ae = doc.get("authorization_endpoint", "")
            if ae in seen_docs:
                continue
            seen_docs.add(ae)
            flows = ", ".join(doc.get("grant_types_supported", [])[:6]) or "?"
            implicit = "token" in (doc.get("response_types_supported") or [])
            out.append(Finding(
                title="OIDC/OAuth discovery document exposed",
                severity="info", category="misconfig", target=urljoin(base, wk),
                evidence=f"authorization_endpoint={ae}; token_endpoint="
                         f"{doc.get('token_endpoint','?')}; grant_types={flows}"
                         + ("; implicit flow ('token') still enabled" if implicit else ""),
                recommendation=("Map the OAuth surface from here. If the implicit flow "
                                "is enabled, prefer auth-code+PKCE. Verify redirect_uri "
                                "is exact-matched and state/nonce are enforced."),
                confidence="firm"))
    return out


def _test_redirect_uri(client: Client, authz_url: str) -> List[Finding]:
    pr = urlparse(authz_url)
    qs = parse_qs(pr.query)
    real_redirect = qs.get("redirect_uri", [""])[0]
    if not real_redirect:
        return []
    legit = urlparse(real_redirect).netloc or real_redirect
    attacker = f"oauthpoc{_rand()}.example"

    # 1) sanity: the real redirect must NOT be rejected, else endpoint unusable
    base_resp = client.get(_set_redirect(authz_url, real_redirect),
                           phase="active", allow_redirects=False)
    if _rejected(base_resp):
        return []

    # 2) control: an unrelated attacker host. If accepted+reflected => accepts ANY.
    ctrl = f"https://{attacker}/cb"
    ctrl_resp = client.get(_set_redirect(authz_url, ctrl), phase="active",
                           allow_redirects=False)
    if not _rejected(ctrl_resp) and _reflects(ctrl_resp, attacker):
        return [_redirect_finding(authz_url, ctrl,
                "arbitrary redirect_uri accepted (no validation)")]

    # 3) validator present — try confusion shapes that smuggle the same attacker host
    variants = [
        (f"https://{legit}.{attacker}/cb", "subdomain-suffix confusion"),
        (f"https://{attacker}/{legit}",    "legit host embedded in path"),
        (f"https://{legit}@{attacker}/cb", "userinfo (@) host confusion"),
    ]
    for redirect, technique in variants:
        if client.over_budget():
            break
        vr = client.get(_set_redirect(authz_url, redirect), phase="active",
                        allow_redirects=False)
        if not _rejected(vr) and _reflects(vr, attacker):
            return [_redirect_finding(authz_url, redirect,
                    f"redirect_uri validation bypass via {technique}")]
    return []


def _redirect_finding(authz_url: str, evil_redirect: str, how: str) -> Finding:
    return Finding(
        title="OAuth redirect_uri validation weakness (authorization-code/token theft)",
        severity="high", category="misconfig", target=authz_url,
        evidence=f"{how}: the authorization endpoint did not reject "
                 f"redirect_uri={evil_redirect} and carried it forward. An attacker "
                 f"redirect_uri leaks the auth code/token -> account takeover.",
        recommendation=("Exact-string-match redirect_uri against a registered "
                        "allow-list (scheme+host+path), reject everything else, and "
                        "enforce PKCE + state. Do not prefix/substring/normalize match."),
        confidence="confirmed",
        poc=f"GET {_set_redirect(authz_url, evil_redirect)}")


def _test_missing_state(client: Client, authz_url: str) -> List[Finding]:
    if "state=" not in urlparse(authz_url).query.lower():
        return []
    with_state = client.get(authz_url, phase="active", allow_redirects=False)
    if _rejected(with_state):
        return []
    without = client.get(_drop_state(authz_url), phase="active", allow_redirects=False)
    if _rejected(without):
        return []
    blob = without.headers.get("location", "") + " " + (without.text or "")[:3000]
    if _STATE_REQUIRED.search(blob):
        return []
    # both proceed; the server did not demand state -> CSRF on the OAuth flow
    return [Finding(
        title="OAuth flow proceeds without 'state' (login CSRF / code fixation)",
        severity="medium", category="misconfig", target=authz_url,
        evidence="the authorization request completed the same way with the `state` "
                 "parameter removed — no CSRF token is enforced on the OAuth flow.",
        recommendation=("Require an unguessable `state` (and `nonce` for OIDC) on "
                        "every authorization request and verify it on callback."),
        confidence="firm")]


def check(client: Client, base_urls: List[str], endpoints: List[dict],
          cfg: Config, scope: Scope) -> List[Finding]:
    if not getattr(cfg, "do_oauth", True) or not base_urls:
        return []
    findings: List[Finding] = []
    findings += _discovery(client, base_urls, scope)
    authz_urls = _harvest_authorize(base_urls, endpoints, scope)
    if authz_urls:
        log("info", f"OAuth: testing {len(authz_urls)} live authorize endpoint(s)")
    for au in authz_urls:
        if client.over_budget():
            break
        findings += _test_redirect_uri(client, au)
        findings += _test_missing_state(client, au)
    if findings:
        log("ok", f"OAuth: {len(findings)} finding(s)")
    return findings

"""403/401 access-control bypass probing (read-only).

For every endpoint that answers 401/403 (or an auth redirect), try the classic
bypass matrix — path mutations, trusted-header spoofs, and safe method swaps —
and flag any that return a 2xx the baseline denied. Pure GET/HEAD/OPTIONS/POST
with empty bodies; nothing is modified.
"""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse, urljoin

from ..config import Config
from ..data import (BYPASS_HEADERS, BYPASS_METHODS, BYPASS_METHOD_OVERRIDE,
                    BYPASS_PATH_MUTATIONS)
from ..http import Client
from ..utils import dedup_keep_order, log
from ..vuln import Finding

_GATED = {401, 403}
_REDIRECT = {301, 302, 303, 307, 308}
_AUTH_LOC = ("login", "signin", "sign-in", "auth", "sso", "account/login",
             "session", "oauth")


def _auth_redirect(status: int, location: str) -> bool:
    """A redirect counts as an access gate only if it points at auth — a generic
    302 (trailing slash, canonicalization) is not a protection to bypass."""
    return status in _REDIRECT and any(k in (location or "").lower() for k in _AUTH_LOC)


def _candidates(base_urls: List[str], discovered: List[dict]) -> List[str]:
    urls = []
    for d in discovered:
        st = d.get("status")
        if st in _GATED or _auth_redirect(st, d.get("location", "")):
            urls.append(d["url"])
    return dedup_keep_order(urls)[:8]


def _path_of(url: str) -> str:
    return urlparse(url).path.lstrip("/") or ""


def _swapcase_last(path: str) -> str:
    segs = path.split("/")
    segs[-1] = segs[-1].swapcase()
    return "/".join(segs)


def _ref_pages(client: Client, root: str, cache: dict) -> list:
    """(status,len) of the site root and a random path — a 200 that matches
    either is a collapse to homepage / soft-404, NOT a real bypass."""
    if root in cache:
        return cache[root]
    refs = []
    import secrets
    for p in ("/", "/" + secrets.token_hex(8) + "/recon-nope"):
        rr = client.get(root + p, phase="active", allow_redirects=False)
        if rr.ok:
            refs.append((rr.status, len(rr.text or "")))
    cache[root] = refs
    return refs


def _valid(r, baseline: int, refs: list, min_body: int = 1) -> bool:
    if not (r.ok and 200 <= r.status < 300 and r.status != baseline):
        return False
    blen = len(r.text or "")
    if blen < min_body:
        return False  # empty/metadata response (OPTIONS/HEAD) — not the resource
    for rs, rl in refs:
        if r.status == rs and abs(blen - rl) <= max(48, int(rl * 0.05)):
            return False  # collapsed to root / soft-404
    return True


def check(client: Client, base_urls: List[str], discovered: List[dict],
          cfg: Config) -> List[Finding]:
    targets = _candidates(base_urls, discovered)
    if not targets:
        return []
    log("info", f"403/401 bypass matrix on {len(targets)} gated endpoint(s)")
    findings: List[Finding] = []
    ref_cache: dict = {}

    for url in targets:
        pr = urlparse(url)
        root = f"{pr.scheme}://{pr.netloc}"
        path = _path_of(url)
        base = client.get(url, phase="active", allow_redirects=False)
        gated = base.ok and (base.status in _GATED or
                             _auth_redirect(base.status, base.headers.get("location", "")))
        if not gated:
            continue
        baseline = base.status
        refs = _ref_pages(client, root, ref_cache)

        hit = None

        # 1) path mutations
        for mut in BYPASS_PATH_MUTATIONS:
            test = root + mut.replace("{P}", path)
            r = client.get(test, phase="active", allow_redirects=False)
            if _valid(r, baseline, refs):
                hit = ("path mutation", test, r.status)
                break

        # 2) trusted-header spoofs
        if not hit:
            for hdr in BYPASS_HEADERS:
                h = {k: v.replace("{P}", "/" + path) for k, v in hdr.items()}
                r = client.get(url, phase="active", allow_redirects=False,
                               extra_headers=h)
                if _valid(r, baseline, refs):
                    hit = (f"header {list(h)[0]}", url, r.status)
                    break

        # 3) safe method swaps (require real content, not an empty/metadata reply)
        if not hit:
            for m in BYPASS_METHODS:
                r = client.request(m, url, phase="active", allow_redirects=False)
                if _valid(r, baseline, refs, min_body=100):
                    hit = (f"method {m}", url, r.status)
                    break

        # 4) method-override headers (GET that claims to be another verb)
        if not hit:
            for hdr in BYPASS_METHOD_OVERRIDE:
                for mv in ("GET", "POST"):
                    r = client.get(url, phase="active", allow_redirects=False,
                                   extra_headers={hdr: mv})
                    if _valid(r, baseline, refs, min_body=100):
                        hit = (f"override {hdr}:{mv}", url, r.status)
                        break
                if hit:
                    break

        # 5) case toggle on the last path segment (case-sensitive ACL bypass)
        if not hit and path:
            for variant in (path.upper(), path.capitalize(),
                            _swapcase_last(path)):
                if variant == path:
                    continue
                r = client.get(root + "/" + variant, phase="active", allow_redirects=False)
                if _valid(r, baseline, refs):
                    hit = ("path case toggle", root + "/" + variant, r.status)
                    break

        if hit:
            technique, test_url, code = hit
            findings.append(Finding(
                title="Access-control bypass (403/401 bypassed)",
                severity="high", category="bypass", target=url,
                evidence=f"baseline {baseline} -> {code} via {technique} ({test_url})",
                recommendation=("Manually confirm the bypassed response exposes "
                                "protected content/functionality, then report the "
                                "access-control gap. Normalize path handling and "
                                "stop trusting client-supplied IP/URL headers."),
                confidence="firm"))
            log("vuln", f"[high] 403 bypass: {url} via {technique} -> {code}")
    return findings

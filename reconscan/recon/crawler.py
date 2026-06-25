"""Recursive in-scope crawler — the single highest-leverage surface expander.

BFS-crawls HTML reachable from the seed set and harvests everything the later
phases feed on:
  * every in-scope URL (parameterized ones especially -> SQLi/XSS/IDOR/LFI/SSTI
    injection targets),
  * <form> action/method/fields (-> exploit surface, even on deep pages that the
    capped build_surface fetch would never reach),
  * the union of parameter names seen.

Every fetch goes through the rate-limited, scope-gated, audited Client, exactly
like the rest of the tool. The crawl is bounded three ways so it can never trap
on infinite parameter permutations or runaway link graphs:
  * a max depth (cfg.crawl_depth),
  * a global page budget (cfg.crawl_max_pages),
  * a per-(host,path) variant cap (so /search?q=1, /search?q=2 ... don't explode).

When katana (ProjectDiscovery) is present it is used as an OPTIONAL breadth
accelerator — its output is re-filtered through the scope guard before use, so a
crawler scope slip can't leak the tool out of bounds. Native crawl always runs.
"""
from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set
from urllib.parse import urljoin, urldefrag, urlparse, parse_qsl

from ..config import Config
from ..http import Client
from ..utils import Scope, dedup_keep_order, is_catch_all_artifact, is_logout_url, log

# href/src on a/link/area/iframe/frame/form... — one cheap pass over the body.
_LINK = re.compile(r"""(?:href|src|action)\s*=\s*['"]?([^'"\s>]+)""", re.I)
_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv\s*=\s*['"]?refresh['"]?[^>]*"""
                           r"""content\s*=\s*['"][^;]*;\s*url=([^'"]+)['"]""", re.I)

# extensions we RECORD as surface but never RECURSE into (not HTML, no links).
_STATIC_EXT = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".avif", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".gz", ".tgz", ".tar", ".rar", ".7z", ".mp4", ".mp3",
    ".webm", ".mov", ".avi", ".wav", ".flac", ".doc", ".docx", ".xls", ".xlsx",
    ".ppt", ".pptx", ".map", ".wasm",
)
# don't recurse these either (structured data, not a link source) but DO record.
_NOFOLLOW_EXT = (".json", ".xml", ".csv", ".txt", ".yaml", ".yml")

_PER_PATH_CAP = 4          # max distinct query-variants crawled per (host, path)
_PER_PATH_RECORD_CAP = 3   # max distinct query-variants RECORDED per (host, path)
                           # — one representative is enough for injection (the
                           # modules test the param, not its value); this kills the
                           # cache-buster explosion (e.g. /socket.io/?t=…&sid=… with
                           # a fresh token every poll) without guessing param names.


def _norm(url: str) -> str:
    """Drop the fragment; leave scheme/host/path/query intact."""
    return urldefrag(url)[0]


def _path_key(url: str) -> str:
    pr = urlparse(url)
    return f"{pr.netloc}{pr.path}"


def _ext(path: str) -> str:
    seg = path.rsplit("/", 1)[-1]
    dot = seg.rfind(".")
    return seg[dot:].lower() if dot >= 0 else ""


def _is_html_candidate(url: str) -> bool:
    """Worth fetching as a page to recurse into?"""
    e = _ext(urlparse(url).path)
    return e not in _STATIC_EXT and e not in _NOFOLLOW_EXT


def _extract_links(body: str, base: str) -> List[str]:
    out: List[str] = []
    for m in _LINK.finditer(body or ""):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("data:", "mailto:", "tel:", "javascript:", "#")):
            continue
        if raw.startswith("//"):
            raw = urlparse(base).scheme + ":" + raw
        out.append(_norm(urljoin(base, raw)))
    for m in _META_REFRESH.finditer(body or ""):
        out.append(_norm(urljoin(base, m.group(1).strip())))
    return out


def _parse_forms_safe(html: str, base: str, scope: Scope) -> List[dict]:
    """Reuse the tested form parser without a hard import cycle (recon<-exploit)."""
    try:
        from ..exploit.forms import _parse_forms
        return _parse_forms(html, base, scope)
    except Exception:
        return []


def _katana_urls(seeds: List[str], scope: Scope, cfg: Config, audit) -> List[str]:
    """Optional breadth accelerator. Returns [] unless the binary is present and
    enabled. Output is hard-filtered through the scope guard by the caller."""
    if not getattr(cfg, "use_katana", True):
        return []
    from ..external import have, run
    if not have("katana"):
        return []
    apex_seeds = dedup_keep_order(seeds)[:10]
    rate = max(1, int(1.0 / cfg.min_interval)) if cfg.min_interval > 0 else 50
    cmd = ["katana", "-silent", "-nc", "-jc",
           "-d", str(max(1, cfg.crawl_depth)),
           "-fs", "rdn",                       # stay within the root domain
           "-rl", str(rate),
           "-timeout", str(int(cfg.timeout)),
           "-c", str(max(1, cfg.threads)),
           "-u", ",".join(apex_seeds)]
    log("info", "katana augment (in-scope crawl accelerator)")
    proc = run(cmd, timeout=180, audit=audit, phase="crawl")
    if proc.returncode not in (0, 124):
        return []
    return [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]


def crawl(client: Client, scope: Scope, seeds: List[str], cfg: Config,
          audit=None) -> Dict[str, object]:
    """BFS in-scope crawl. Returns {pages_crawled, urls, forms, params,
    katana_used}. Safe to call with an empty seed list."""
    log("step", "Recursive crawl (in-scope surface expansion)")
    max_pages = max(1, getattr(cfg, "crawl_max_pages", 150))
    max_depth = max(0, getattr(cfg, "crawl_depth", 3))

    seen_urls: Set[str] = set()        # every in-scope URL recorded (surface)
    visited: Set[str] = set()          # pages actually fetched
    path_variants: Dict[str, int] = {}
    record_variants: Dict[str, int] = {}
    forms: List[dict] = []
    params: Set[str] = set()
    q: deque = deque()

    def record(url: str) -> None:
        u = _norm(url)
        if u in seen_urls or not scope.url_in_scope(u):
            return
        if any(tok in u for tok in ("${", "{{", "}}", "`", "<", ">")):
            return  # unresolved template literal / junk (common in katana JS parsing)
        if is_catch_all_artifact(u):
            return  # /.env/socket.io/ style soft-404 artifact on catch-all hosts
        if is_logout_url(u):
            return  # never put logout/sign-out in the surface (would drop an authed session)
        # cap recorded query-variants per path so a cache-buster (unique ?t=/&sid=
        # every request) can't balloon the surface into thousands of dead URLs.
        pk = _path_key(u)
        if "?" in u:
            if record_variants.get(pk, 0) >= _PER_PATH_RECORD_CAP:
                return
            record_variants[pk] = record_variants.get(pk, 0) + 1
        seen_urls.add(u)
        for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True):
            params.add(k)

    def enqueue(url: str, depth: int) -> None:
        u = _norm(url)
        if u in visited or not scope.url_in_scope(u) or not _is_html_candidate(u):
            return
        if any(tok in u for tok in ("${", "{{", "}}", "`", "<", ">")):
            return
        if is_catch_all_artifact(u) or is_logout_url(u):
            return
        pk = _path_key(u)
        if path_variants.get(pk, 0) >= _PER_PATH_CAP:
            return
        path_variants[pk] = path_variants.get(pk, 0) + 1
        q.append((u, depth))
        visited.add(u)

    # seed (record everything, enqueue the crawlable ones at depth 0)
    for s in dedup_keep_order(seeds):
        if s.startswith("//"):
            s = "https:" + s
        if not s.startswith("http"):
            continue
        record(s)
        enqueue(s, 0)

    # optional katana breadth pass — fold its URLs into the seed/record set
    katana_used = False
    for ku in _katana_urls(seeds, scope, cfg, audit):
        if scope.url_in_scope(ku):
            katana_used = True
            record(ku)
            enqueue(ku, 1)

    pages = 0
    while q and pages < max_pages:
        if client.over_budget():
            log("warn", "crawl stopped early: request budget reached")
            break
        url, depth = q.popleft()
        r = client.get(url, phase="crawl")
        if not r.ok:
            continue
        pages += 1
        ctype = r.headers.get("content-type", "").lower()
        if "html" not in ctype and "xml" not in ctype:
            continue
        body = r.text or ""
        forms += _parse_forms_safe(body, r.final_url or url, scope)
        for link in _extract_links(body, r.final_url or url):
            record(link)
            if depth + 1 <= max_depth:
                enqueue(link, depth + 1)

    # dedupe forms by (host+path, method, field-names); prefer https action
    fbest: Dict[tuple, dict] = {}
    for f in forms:
        pr = urlparse(f["action"])
        key = (pr.netloc, pr.path, f["method"],
               tuple(sorted(x["name"] for x in f["fields"])))
        cur = fbest.get(key)
        if cur is None or (pr.scheme == "https"
                           and urlparse(cur["action"]).scheme != "https"):
            fbest[key] = f

    # param-bearing URLs first (highest injection value)
    urls = sorted(seen_urls, key=lambda u: ("?" not in u, u))
    log("ok", f"crawl: {pages} page(s) fetched, {len(urls)} in-scope URL(s), "
             f"{len(fbest)} form(s), {len(params)} param name(s)"
             + (" (+katana)" if katana_used else ""))
    return {
        "pages_crawled": pages,
        "urls": urls,
        "forms": list(fbest.values()),
        "params": sorted(params),
        "katana_used": katana_used,
    }

"""Endpoint / directory discovery.

  * robots.txt + sitemap.xml parsing (passive, low-noise)
  * optional small wordlist directory probe (rate-limited)

Non-destructive: GET/HEAD only, no parameter fuzzing.
"""
from __future__ import annotations

import concurrent.futures as cf
import re
import secrets
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..config import Config
from ..data import DIR_WORDS
from ..http import Client
from ..utils import dedup_keep_order, log


def _parse_robots(text: str) -> List[str]:
    paths = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"(?:dis)?allow\s*:\s*(\S+)", line, re.I)
        if m and m.group(1) not in ("/", "*"):
            paths.append(m.group(1))
        m2 = re.match(r"sitemap\s*:\s*(\S+)", line, re.I)
        if m2:
            paths.append(m2.group(1))
    return paths


def _parse_sitemap(text: str) -> List[str]:
    return re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I)[:200]


def _load_dir_words(cfg: Config) -> List[str]:
    if cfg.dir_wordlist:
        try:
            with open(cfg.dir_wordlist, encoding="utf-8") as fh:
                return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            log("warn", f"dir wordlist unreadable ({e}); using built-in")
    return DIR_WORDS


def discover(client: Client, base_url: str, cfg: Config) -> dict:
    log("step", f"Endpoint discovery on {base_url}")
    result = {"base_url": base_url, "robots": [], "sitemap": [],
              "discovered": []}

    # robots.txt
    r = client.get(urljoin(base_url, "/robots.txt"), phase="endpoints")
    if r.ok and r.status == 200 and "text" not in r.headers.get("content-type", "html"):
        pass
    if r.ok and r.status == 200:
        robots_paths = _parse_robots(r.text)
        result["robots"] = robots_paths
        if robots_paths:
            log("ok", f"robots.txt: {len(robots_paths)} entries")

    # sitemap.xml
    s = client.get(urljoin(base_url, "/sitemap.xml"), phase="endpoints")
    if s.ok and s.status == 200 and "<" in s.text:
        locs = _parse_sitemap(s.text)
        result["sitemap"] = locs
        if locs:
            log("ok", f"sitemap.xml: {len(locs)} URLs")

    # optional dir brute
    if cfg.dir_brute:
        words = _load_dir_words(cfg)
        log("info", f"directory probe ({len(words)} paths)")
        found: List[dict] = []

        # catch-all baseline: a guaranteed-missing path. On an SPA / catch-all host
        # that answers 200+index for EVERY path, every word would otherwise look
        # "discovered" and flood the surface (and waste budget) — so 200s that are
        # size-identical to this not-found baseline are dropped. Real endpoints
        # differ in status or body size, so this never hides a true discovery.
        cax = client.get(urljoin(base_url, f"/{secrets.token_hex(12)}-nf"),
                         phase="endpoints", allow_redirects=False)
        cax_200 = cax.ok and cax.status == 200
        cax_len = len(cax.text or "")

        def probe(path: str):
            url = urljoin(base_url, "/" + path.lstrip("/"))
            resp = client.get(url, phase="endpoints", allow_redirects=False)
            if not (resp.ok and resp.status not in (404, 0)):
                return None
            if cax_200 and resp.status == 200 and \
                    abs(len(resp.text or "") - cax_len) <= max(64, cax_len * 0.05):
                return None
            return {
                "url": url, "status": resp.status,
                "length": len(resp.text),
                "location": resp.headers.get("location", ""),
                "content_type": resp.headers.get("content-type", ""),
            }

        with cf.ThreadPoolExecutor(max_workers=max(2, cfg.threads)) as ex:
            for res in ex.map(probe, words):
                if res:
                    found.append(res)
                    log("ok", f"[{res['status']}] {res['url']}", detail=True)
        result["discovered"] = sorted(found, key=lambda x: x["url"])

    return result

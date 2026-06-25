"""Historical URL mining via the Wayback Machine CDX API (keyless).

The Internet Archive's CDX endpoint is a public, no-key OSINT source (same class
as crt.sh). We query it directly — not through the scoped Client — then
scope-filter the results so only the target's own historical URLs are kept.
Great for surfacing forgotten endpoints, old parameters, and stale files that no
longer appear in the live site but may still be reachable.
"""
from __future__ import annotations

from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests

from ..audit import AuditLog
from ..data import JUICY_EXTENSIONS, JUICY_KEYWORDS
from ..utils import Scope, dedup_keep_order, log

CDX_URL = "http://web.archive.org/cdx/search/cdx"


def _is_juicy(url: str) -> bool:
    low = url.lower()
    path = urlparse(low).path
    if path.endswith(JUICY_EXTENSIONS):
        return True
    return any(k in low for k in JUICY_KEYWORDS)


def mine(apex: str, scope: Scope, audit: AuditLog, *, limit: int = 5000,
         timeout: float = 30.0) -> Tuple[List[str], Dict[str, object]]:
    """Returns (juicy_urls, summary). summary has total, in_scope, juicy counts."""
    log("step", "Wayback historical URL mining (CDX)")
    params = {
        "url": f"*.{apex}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    audit.record("GET", CDX_URL + f"?url=*.{apex}/*", phase="wayback",
                 tool="web.archive.org", note="historical URL mining")
    try:
        r = requests.get(CDX_URL, params=params, timeout=timeout,
                         headers={"User-Agent": "reconscan/0.2"})
        rows = r.json() if r.status_code == 200 else []
    except (requests.RequestException, ValueError) as e:
        log("warn", f"wayback CDX unavailable: {type(e).__name__}")
        return [], {"total": 0, "in_scope": 0, "juicy": 0, "error": type(e).__name__}

    # first row is the header when fl=original returns [["original"], ...]
    urls = [row[0] for row in rows[1:] if row] if rows and rows[0] == ["original"] \
        else [row[0] for row in rows if row]
    urls = dedup_keep_order(urls)

    in_scope = [u for u in urls if scope.url_in_scope(u)]
    juicy = dedup_keep_order([u for u in in_scope if _is_juicy(u)])

    log("ok", f"wayback: {len(urls)} archived URLs, {len(in_scope)} in-scope, "
              f"{len(juicy)} juicy")
    for u in juicy[:15]:
        log("info", f"  juicy: {u}")
    summary = {
        "total": len(urls),
        "in_scope": len(in_scope),
        "juicy": len(juicy),
        "juicy_urls": juicy[:200],
    }
    return juicy, summary

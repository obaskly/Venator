"""Hidden-parameter discovery (Arjun-style).

A parameter the application reads but never advertises is fresh, untested attack
surface — the place IDOR / SQLi / SSRF / open-redirect actually live. This mines
for them: fire batches of candidate names carrying a unique canary value and look
for the canary reflected back (high-signal) or a stable response-size shift
(weaker). Confirmed params are folded into the exploitation surface so the
injection modules test them.

GET-only, capped, rate-limited, scope-gated. Detection technique, not an attack.
"""
from __future__ import annotations

import secrets
from typing import List, Set
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..config import Config
from ..data import PARAM_WORDS
from ..http import Client
from ..utils import dedup_keep_order, log

_CHUNK = 24
_MAX_SEEDS = 8
_STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
           ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip", ".mp4")


def _load_words(cfg: Config) -> List[str]:
    if cfg.param_wordlist:
        try:
            with open(cfg.param_wordlist, encoding="utf-8") as fh:
                return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            log("warn", f"param wordlist unreadable ({e}); using built-in")
    return PARAM_WORDS


def _with_params(url: str, names: List[str], canary: str) -> str:
    pr = urlparse(url)
    qs = dict(parse_qsl(pr.query, keep_blank_values=True))
    for n in names:
        qs[n] = canary
    return urlunparse(pr._replace(query=urlencode(qs)))


def _seed_ok(url: str) -> bool:
    pr = urlparse(url)
    return bool(pr.scheme.startswith("http")) and not pr.path.lower().endswith(_STATIC)


def _find_reflecting(client, url, names, baseline_has_canary) -> List[str]:
    """Binary-search a chunk for the param(s) whose value reflects."""
    if not names:
        return []
    canary = "rmp" + secrets.token_hex(4)
    r = client.get(_with_params(url, names, canary), phase="parammine")
    if not r.ok or canary not in (r.text or ""):
        return []
    if len(names) == 1:
        return names
    mid = len(names) // 2
    return (_find_reflecting(client, url, names[:mid], baseline_has_canary) +
            _find_reflecting(client, url, names[mid:], baseline_has_canary))


def mine(client: Client, seed_urls: List[str], cfg: Config) -> List[str]:
    if not cfg.do_parammine:
        return []
    seeds = [u for u in dedup_keep_order(seed_urls) if _seed_ok(u)][:_MAX_SEEDS]
    if not seeds:
        return []
    words = _load_words(cfg)
    log("info", f"param mining: {len(words)} candidate names over {len(seeds)} URL(s)")
    found: List[str] = []
    discovered_pairs: Set[tuple] = set()

    for url in seeds:
        if client.over_budget():
            break
        # control: does a random never-used param name already reflect? if so the
        # page echoes everything and reflection is meaningless here — skip it.
        ctrl = "rmp" + secrets.token_hex(4)
        cr = client.get(_with_params(url, ["zz" + secrets.token_hex(3)], ctrl),
                        phase="parammine")
        if cr.ok and ctrl in (cr.text or ""):
            continue
        for i in range(0, len(words), _CHUNK):
            if client.over_budget():
                break
            chunk = words[i:i + _CHUNK]
            hits = _find_reflecting(client, url, chunk, False)
            for name in hits:
                key = (urlparse(url).path, name)
                if key in discovered_pairs:
                    continue
                discovered_pairs.add(key)
                found.append(_with_params(url, [name], "1"))
                log("ok", f"hidden param: '{name}' reflected @ {urlparse(url).path}")

    if found:
        log("ok", f"param mining: {len(found)} hidden parameter(s) added to surface")
    return found

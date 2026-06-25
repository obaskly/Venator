"""Small shared helpers: scope guard, logging, normalization."""
from __future__ import annotations

import re
import sys
import threading
import time
from typing import Iterable, List
from urllib.parse import urlparse


# ---------------------------------------------------------------- console log
_C = {
    "reset": "\033[0m", "dim": "\033[2m", "red": "\033[31m", "grn": "\033[32m",
    "yel": "\033[33m", "blu": "\033[34m", "mag": "\033[35m", "cyn": "\033[36m",
    "bold": "\033[1m",
}
_use_color = sys.stdout.isatty()
_print_lock = threading.Lock()

# Verbosity: -1 quiet, 0 normal, 1 verbose. Controls per-request "detail" noise
# (out-of-scope blocks, per-path hits) which explodes across many subdomains.
_VERBOSITY = 0
_suppressed = 0


def set_verbosity(level: int) -> None:
    global _VERBOSITY
    _VERBOSITY = level


def suppressed_count() -> int:
    return _suppressed


def _c(s: str, color: str) -> str:
    if not _use_color:
        return s
    return f"{_C.get(color, '')}{s}{_C['reset']}"


def log(level: str, msg: str, detail: bool = False) -> None:
    """detail=True lines are per-request noise: shown only at -v (verbose).
    In quiet mode (-q) only warnings/errors/vulns/steps print."""
    global _suppressed
    if detail and _VERBOSITY < 1:
        _suppressed += 1
        return
    if _VERBOSITY < 0 and level in ("info", "ok"):
        return
    tags = {
        "info": ("[*]", "cyn"), "ok": ("[+]", "grn"), "warn": ("[!]", "yel"),
        "err": ("[x]", "red"), "vuln": ("[V]", "mag"), "step": ("==>", "blu"),
    }
    tag, color = tags.get(level, ("[*]", "cyn"))
    with _print_lock:
        print(f"{_c(tag, color)} {msg}", flush=True)


# ---------------------------------------------------------------- scope guard
class ScopeError(Exception):
    pass


class Scope:
    """Hard gate: only the apex domain, its subdomains, and explicit extras
    are ever contacted. Anything else raises ScopeError."""

    def __init__(self, apex: str, extras: Iterable[str] = ()):
        # strip any :port so a target like "host:8080" still matches host "host"
        # (host_in_scope strips the port from the candidate side too)
        self.apex = apex.lower().rstrip(".").split(":", 1)[0]
        self.extras = {e.lower().rstrip(".").split(":", 1)[0] for e in extras}

    def host_in_scope(self, host: str) -> bool:
        if not host:
            return False
        host = host.lower().rstrip(".")
        # strip port if present
        host = host.split(":", 1)[0]
        if host == self.apex or host.endswith("." + self.apex):
            return True
        if host in self.extras or any(host.endswith("." + e) for e in self.extras):
            return True
        # raw IP that we explicitly allow-listed
        if host in self.extras:
            return True
        return False

    def url_in_scope(self, url: str) -> bool:
        try:
            netloc = urlparse(url).netloc or urlparse("//" + url).netloc
        except Exception:
            return False
        return self.host_in_scope(netloc)

    def assert_url(self, url: str) -> None:
        if not self.url_in_scope(url):
            raise ScopeError(f"OUT OF SCOPE blocked: {url}")


# ---------------------------------------------------------------- rate limiter
class RateLimiter:
    """Global minimum spacing between outbound requests. Thread-safe."""

    def __init__(self, min_interval: float):
        self.min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next_allowed - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next_allowed = now + self.min_interval


# ---------------------------------------------------------------- misc
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def valid_hostname(h: str) -> bool:
    h = h.strip().lower().rstrip(".")
    return bool(_HOST_RE.match(h))


def dedup_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# dot-prefixed path segments that are legitimately directories (a real endpoint
# can live UNDER them), so they must not be treated as catch-all junk: the
# standard web dir + the VCS metadata dirs the exposure checks legitimately walk.
_DOT_DIR_OK = {".well-known", ".git", ".svn", ".hg", ".bzr"}


def is_catch_all_artifact(url: str) -> bool:
    """True for URLs that only exist because the host serves 200 for EVERY path
    (a catch-all SPA / soft-404 host): a dotfile or dot-dir shows up as a
    NON-terminal path segment, e.g. ``/.env/socket.io/`` or ``/.git/main.js``.
    A real dotfile (``/.env``, ``/.git/HEAD``) is requested as a leaf; a dotfile
    with more path glued AFTER it is a relative-URL-against-soft-404 artifact and
    is never a real endpoint. These flood the crawl + waste the request budget on
    catch-all targets, so the surface builders drop them. ``.well-known`` is a
    genuine directory and is exempt."""
    try:
        path = urlparse(url).path
    except Exception:
        return False
    segs = [s for s in path.split("/") if s]
    for s in segs[:-1]:                       # every segment except the last
        if s.startswith(".") and s.lower() not in _DOT_DIR_OK:
            return True
    return False


_LOGOUT_RE = re.compile(
    r"(?:^|[/_\-.=])(logout|log-out|signout|sign-out|logoff|log-off|"
    r"signoff|deauth|deauthenticate|/exit|session/destroy|account/logout)"
    r"(?:$|[/_\-.?&])", re.I)


def is_logout_url(url: str) -> bool:
    """True for logout / sign-out / session-destroy URLs. Following one during an
    AUTHENTICATED scan destroys the session and silently cripples every later
    authed check (IDOR/BOLA/dashboard), so the crawler, headless browser, and
    surface builders skip these entirely — they are never a useful attack target."""
    try:
        pr = urlparse(url)
    except Exception:
        return False
    return bool(_LOGOUT_RE.search(pr.path + (("?" + pr.query) if pr.query else "")))


def title_from_html(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]

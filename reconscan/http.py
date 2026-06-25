"""Rate-limited, scope-gated, audit-logged HTTP client.

Every request goes through here so that:
  * the global RateLimiter enforces conservative spacing,
  * the Scope guard blocks any out-of-scope host,
  * the AuditLog records method/url/timestamp/status.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .audit import AuditLog
from .config import Config
from .data import USER_AGENTS
from .utils import RateLimiter, Scope, ScopeError, log

_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class Response:
    url: str
    final_url: str
    status: int
    headers: dict
    text: str
    elapsed: float
    redirects: list
    error: str = ""
    offscope_redirect: bool = False   # final hop pointed OUT of scope; not fetched
    final_host_in_scope: bool = True

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status > 0


class Client:
    def __init__(self, config: Config, scope: Scope, audit: AuditLog):
        self.cfg = config
        self.scope = scope
        self.audit = audit
        self.limiter = RateLimiter(config.min_interval)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent,
                                     "Accept": "*/*"})
        if not config.verify_tls:
            # We intentionally don't verify certs during recon; silence the noise.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # connection-level retries only (rate limiter handles spacing)
        retry = Retry(total=0, connect=config.max_retries, read=0,
                      backoff_factor=0.5, status_forcelist=[])
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=config.threads * 2)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.auth_token = None
        self._req_count = 0
        self._budget_warned = False
        # user-supplied authentication (so every phase runs authenticated) —
        # remembered so a mid-scan captured-token clear_auth() restores it.
        self._user_auth: dict = {}
        self._apply_user_auth(config)

    def _apply_user_auth(self, cfg: Config) -> None:
        """Attach a user-provided session: --auth-bearer, --header, --cookie.
        These persist for the whole scan (only ever sent to in-scope hosts)."""
        applied = []
        if getattr(cfg, "auth_bearer", ""):
            self._user_auth["Authorization"] = f"Bearer {cfg.auth_bearer}"
            applied.append("bearer")
        for raw in getattr(cfg, "auth_headers", []) or []:
            if ":" in raw:
                k, v = raw.split(":", 1)
                self._user_auth[k.strip()] = v.strip()
        if self._user_auth:
            self.session.headers.update(self._user_auth)
            applied.append(f"{len(self._user_auth)} header(s)")
        if getattr(cfg, "auth_cookie", ""):
            for part in cfg.auth_cookie.split(";"):
                if "=" in part:
                    name, val = part.split("=", 1)
                    self.session.cookies.set(name.strip(), val.strip())
            applied.append("cookie")
        if applied:
            log("info", f"authenticated session attached ({', '.join(applied)}) — "
                        "all phases run with your credentials")

    def over_budget(self) -> bool:
        """Global request cap (cfg.max_requests, 0=unlimited). A safety valve so a
        runaway scan over many subdomains can't fire unbounded traffic."""
        cap = getattr(self.cfg, "max_requests", 0)
        if cap and self._req_count >= cap:
            if not self._budget_warned:
                self._budget_warned = True
                log("warn", f"request budget reached ({cap}); further requests skipped "
                            f"(raise with --max-requests)")
            return True
        return False

    def set_auth(self, token: str) -> None:
        """Attach a captured bearer token so later phases run authenticated
        (e.g. test IDOR on objects that require a session)."""
        if token:
            self.auth_token = token
            self.session.headers["Authorization"] = f"Bearer {token}"

    def clear_auth(self) -> None:
        """Drop a mid-scan captured bearer, but restore the user-supplied
        Authorization (if any) so the session stays authenticated as the user."""
        self.auth_token = None
        self.session.headers.pop("Authorization", None)
        if self._user_auth.get("Authorization"):
            self.session.headers["Authorization"] = self._user_auth["Authorization"]

    def _single(self, method: str, url: str, phase: str, body_limit: int,
                headers: dict) -> Response:
        """One physical request (NO auto-redirect). Rate-limited + audited."""
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        status = None
        h = dict(headers)
        if self.cfg.rotate_ua and "User-Agent" not in h:
            h["User-Agent"] = random.choice(USER_AGENTS)
        try:
            resp = self.session.request(
                method, url, timeout=self.cfg.timeout,
                allow_redirects=False, verify=self.cfg.verify_tls,
                headers=h or None, stream=True,
            )
            raw = resp.raw.read(body_limit, decode_content=True)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            return Response(
                url=url, final_url=url, status=status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=text, elapsed=resp.elapsed.total_seconds(), redirects=[])
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record(method, url, phase=phase, status=status)

    def request(self, method: str, url: str, *, phase: str = "",
                allow_redirects: bool = True, body_limit: int = 2_000_000,
                extra_headers: Optional[dict] = None, max_hops: int = 5) -> Response:
        # --- scope gate on the initial URL (hard fail, audited) ---
        try:
            self.scope.assert_url(url)
        except ScopeError as e:
            self.audit.record(method, url, phase=phase, note="BLOCKED_OUT_OF_SCOPE")
            log("err", str(e), detail=True)
            return Response(url, url, 0, {}, "", 0.0, [], error="out_of_scope",
                            final_host_in_scope=False)

        base_headers = dict(extra_headers) if extra_headers else {}
        cur_method, cur_url = method, url
        redirects: list = []
        resp = self._single(cur_method, cur_url, phase, body_limit, base_headers)

        # --- manual, scope-checked redirect following ---
        # requests' auto-follow would silently chase a 30x to ANY host; that is a
        # scope bypass. We follow hops ourselves and assert scope on each one.
        hops = 0
        while allow_redirects and resp.ok and resp.status in _REDIRECT_CODES \
                and resp.headers.get("location") and hops < max_hops:
            loc = resp.headers["location"]
            nxt = urljoin(cur_url, loc)
            redirects.append(loc)
            if not self.scope.url_in_scope(nxt):
                # Stop BEFORE fetching the off-scope host. Keep the in-scope 30x
                # response, but mark the final destination as out of scope.
                resp.final_url = nxt
                resp.offscope_redirect = True
                resp.final_host_in_scope = False
                resp.redirects = redirects
                self.audit.record("REDIRECT", nxt, phase=phase,
                                  note="OFF_SCOPE_REDIRECT_NOT_FOLLOWED")
                return resp
            cur_url = nxt
            if resp.status == 303:
                cur_method = "GET"
            resp = self._single(cur_method, cur_url, phase, body_limit, base_headers)
            hops += 1

        resp.final_url = cur_url
        resp.redirects = redirects
        resp.final_host_in_scope = self.scope.url_in_scope(cur_url)
        return resp

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw) -> Response:
        return self.request("HEAD", url, **kw)

    def submit_form(self, url: str, data: dict, method: str = "POST",
                    phase: str = "exploit") -> Response:
        """Submit a urlencoded form (scope-gated, rate-limited, audited).
        Used by the exploitation phase. Follows in-scope redirects."""
        from urllib.parse import urlencode, urlparse, urlunparse
        if method.upper() == "GET":
            pr = urlparse(url)
            return self.get(urlunparse(pr._replace(query=urlencode(data))), phase=phase)
        try:
            self.scope.assert_url(url)
        except ScopeError as e:
            self.audit.record("POST", url, phase=phase, note="BLOCKED_OUT_OF_SCOPE")
            log("err", str(e), detail=True)
            return Response(url, url, 0, {}, "", 0.0, [], error="out_of_scope")
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.cfg.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        status = None
        try:
            resp = self.session.post(url, data=data, timeout=self.cfg.timeout,
                                     allow_redirects=True, verify=self.cfg.verify_tls,
                                     headers=headers, stream=True)
            raw = resp.raw.read(2_000_000, decode_content=True)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            fin = resp.url
            return Response(url, fin, status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            text, resp.elapsed.total_seconds(),
                            [r.headers.get("location", "") for r in resp.history],
                            final_host_in_scope=self.scope.url_in_scope(fin))
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record("POST", url, phase=phase, status=status)

    def post_form(self, url: str, data: dict, phase: str = "exploit") -> Response:
        return self.submit_form(url, data, method="POST", phase=phase)

    def post_raw(self, url: str, body: str, content_type: str,
                 phase: str = "exploit") -> Response:
        """POST a raw body with an explicit Content-Type (scope-gated, audited).
        Used for XXE (XML) and similar."""
        try:
            self.scope.assert_url(url)
        except ScopeError as e:
            self.audit.record("POST", url, phase=phase, note="BLOCKED_OUT_OF_SCOPE")
            return Response(url, url, 0, {}, "", 0.0, [], error="out_of_scope")
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        headers = {"Content-Type": content_type}
        if self.cfg.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        status = None
        try:
            resp = self.session.post(url, data=body.encode("utf-8"),
                                     timeout=self.cfg.timeout, allow_redirects=True,
                                     verify=self.cfg.verify_tls, headers=headers, stream=True)
            raw = resp.raw.read(2_000_000, decode_content=True)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            return Response(url, resp.url, status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            text, resp.elapsed.total_seconds(), [])
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record("POST", url, phase=phase, status=status)

    def post_json(self, url: str, obj, phase: str = "exploit",
                  extra_headers: Optional[dict] = None) -> Response:
        """POST a JSON body (scope-gated, rate-limited, audited). Used for API
        login bypass / NoSQLi against JSON endpoints."""
        import json as _json
        try:
            self.scope.assert_url(url)
        except ScopeError as e:
            self.audit.record("POST", url, phase=phase, note="BLOCKED_OUT_OF_SCOPE")
            log("err", str(e), detail=True)
            return Response(url, url, 0, {}, "", 0.0, [], error="out_of_scope")
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        if self.cfg.rotate_ua and "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        status = None
        try:
            resp = self.session.post(url, data=_json.dumps(obj), timeout=self.cfg.timeout,
                                     allow_redirects=True, verify=self.cfg.verify_tls,
                                     headers=headers, stream=True)
            raw = resp.raw.read(2_000_000, decode_content=True)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            return Response(url, resp.url, status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            text, resp.elapsed.total_seconds(), [])
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record("POST", url, phase=phase, status=status)

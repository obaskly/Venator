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

# Cloud object-storage hosts the bucket-enumeration phase is allowed to contact.
# These are NOT the target; like external_request, calls are credential-isolated
# (a fresh connection, never the target session) so the target's auth never leaks.
CLOUD_HOST_SUFFIXES = ("amazonaws.com", "storage.googleapis.com",
                       "blob.core.windows.net", "r2.dev",
                       "digitaloceanspaces.com", "aliyuncs.com")


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
        self.limiter = RateLimiter(
            config.min_interval,
            adaptive=getattr(config, "adaptive_rate", False),
            max_interval=max(config.min_interval * 20, 30.0))
        self._throttle_warned = False
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

    def _throttle_feedback(self, status, headers) -> None:
        """Feed the adaptive rate limiter: 429/503 -> back off (honour
        Retry-After), clean 2xx/3xx -> ease back toward the floor. No-op unless
        adaptive rate limiting is enabled."""
        if not self.limiter.adaptive or not status:
            return
        if status in (429, 503):
            ra = 0.0
            try:
                ra = float((headers or {}).get("retry-after", "") or 0)
            except (TypeError, ValueError):
                ra = 0.0
            self.limiter.penalize(ra)
            if not self._throttle_warned:
                self._throttle_warned = True
                log("warn", f"server throttling ({status}) — adaptive back-off to "
                            f"{self.limiter.current():.1f}s spacing "
                            f"(disable with --no-adaptive-rate)")
        elif status < 400:
            self.limiter.reward()

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
            self._throttle_feedback(status, resp.headers)
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

    def external_request(self, method: str, url: str, *, headers: dict = None,
                         allow_hosts: tuple = (), phase: str = "secret-validate",
                         body_limit: int = 65_536) -> Response:
        """A single read-only request to a THIRD-PARTY issuer API (NOT the target).

        This is the one outbound path that deliberately leaves the scope guard,
        used only to verify a *leaked credential* against the API that issued it
        (e.g. a found GitHub token against api.github.com/user). It is:
          * host-allowlisted   — the host MUST be in `allow_hosts` (issuer APIs only),
          * credential-isolated — a FRESH request, never `self.session`, so the
            target's auth cookie/bearer is never sent to the third party,
          * rate-limited + budget-capped + audited like every other request,
          * TLS-verified (these are real CA-signed public APIs).
        Opt-in only (`--validate-secrets`); never fires during a default scan.
        """
        host = (urlparse(url).hostname or "").lower()
        if host not in allow_hosts:
            self.audit.record(method, url, phase=phase, note="EXTERNAL_NOT_ALLOWLISTED")
            return Response(url, url, 0, {}, "", 0.0, [], error="not_allowlisted")
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        h = {"User-Agent": self.cfg.user_agent, "Accept": "*/*"}
        if headers:
            h.update(headers)
        status = None
        try:
            resp = requests.request(
                method, url, headers=h, timeout=self.cfg.timeout,
                allow_redirects=False, verify=True, stream=True)
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
            self.audit.record(method, url, phase=phase, status=status,
                              note="EXTERNAL_VALIDATE")

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
            self._throttle_feedback(status, resp.headers)
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

    def burst(self, url: str, data: dict, n: int = 8, method: str = "POST",
              phase: str = "exploit") -> list:
        """Fire `n` IDENTICAL requests as simultaneously as possible — the
        race-condition / TOCTOU probe. A thread Barrier releases every request
        at the same instant.

        The per-request rate limiter is intentionally bypassed for the burst
        window (simultaneity is the whole point), but ONE limiter slot is
        consumed up front so the burst still paces against the rest of the scan,
        and the scope guard + budget + per-request audit all still apply.
        Returns a list of Response objects (may be shorter than n on error)."""
        import threading
        import concurrent.futures as _cf
        try:
            self.scope.assert_url(url)
        except ScopeError as e:
            self.audit.record(method, url, phase=phase, note="BLOCKED_OUT_OF_SCOPE")
            log("err", str(e), detail=True)
            return []
        if self.over_budget():
            return []
        n = max(2, min(int(n), 10))   # hard cap — never a flood
        self.limiter.wait()           # one pacing slot for the whole burst
        self._req_count += n
        barrier = threading.Barrier(n, timeout=self.cfg.timeout)
        form_headers = {"Content-Type": "application/x-www-form-urlencoded"}

        def _fire(_i: int) -> Optional[Response]:
            h = dict(form_headers)
            if self.cfg.rotate_ua:
                h["User-Agent"] = random.choice(USER_AGENTS)
            status = None
            try:
                barrier.wait()        # all threads release together
            except threading.BrokenBarrierError:
                pass
            try:
                resp = self.session.request(
                    method, url, data=data, timeout=self.cfg.timeout,
                    allow_redirects=False, verify=self.cfg.verify_tls,
                    headers=h, stream=True)
                raw = resp.raw.read(300_000, decode_content=True)
                text = raw.decode(resp.encoding or "utf-8", errors="replace")
                status = resp.status_code
                return Response(url, url, status,
                                {k.lower(): v for k, v in resp.headers.items()},
                                text, resp.elapsed.total_seconds(), [])
            except requests.RequestException as e:
                return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
            finally:
                self.audit.record(method, url, phase=phase, status=status,
                                  note="BURST")

        with _cf.ThreadPoolExecutor(max_workers=n) as ex:
            results = [r for r in ex.map(_fire, range(n)) if r is not None]
        return results

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
            self._throttle_feedback(status, resp.headers)
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
            self._throttle_feedback(status, resp.headers)
            return Response(url, resp.url, status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            text, resp.elapsed.total_seconds(), [])
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record("POST", url, phase=phase, status=status)

    def cloud_request(self, method: str, url: str, *, phase: str = "cloud-assets",
                      body_limit: int = 65_536) -> Response:
        """A single read-only request to a CLOUD object-store host (S3/GCS/Azure/
        R2/Spaces) — the bucket-enumeration probe. Like external_request it leaves
        the target scope guard on purpose, but only to an allowlisted cloud host,
        with a FRESH connection (target auth never leaks), rate-limited, budget-
        capped, TLS-verified and audited."""
        host = (urlparse(url).hostname or "").lower()
        if not any(host == s or host.endswith("." + s) for s in CLOUD_HOST_SUFFIXES):
            self.audit.record(method, url, phase=phase, note="CLOUD_NOT_ALLOWLISTED")
            return Response(url, url, 0, {}, "", 0.0, [], error="not_cloud_host")
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        h = {"User-Agent": self.cfg.user_agent, "Accept": "*/*"}
        status = None
        try:
            resp = requests.request(method, url, headers=h, timeout=self.cfg.timeout,
                                    allow_redirects=True, verify=True, stream=True)
            raw = resp.raw.read(body_limit, decode_content=True)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            return Response(url, resp.url, status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            text, resp.elapsed.total_seconds(), [])
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record(method, url, phase=phase, status=status, note="CLOUD_PROBE")

    def post_multipart(self, url: str, fields: dict, files: list,
                       phase: str = "exploit", method: str = "POST",
                       extra_headers: Optional[dict] = None) -> Response:
        """POST a multipart/form-data body — the file-upload probe.

        `fields` are normal form fields (name -> str). `files` is a list of
        (field_name, filename, content_bytes, content_type) tuples. requests sets
        the multipart boundary + Content-Type automatically. Scope-gated,
        rate-limited, budget-capped, audited like every other write."""
        try:
            self.scope.assert_url(url)
        except ScopeError as e:
            self.audit.record(method, url, phase=phase, note="BLOCKED_OUT_OF_SCOPE")
            log("err", str(e), detail=True)
            return Response(url, url, 0, {}, "", 0.0, [], error="out_of_scope")
        if self.over_budget():
            return Response(url, url, 0, {}, "", 0.0, [], error="budget_exceeded")
        self._req_count += 1
        self.limiter.wait()
        multipart = {}
        for fname, filename, content, ctype in files:
            if isinstance(content, str):
                content = content.encode("utf-8", errors="replace")
            multipart[fname] = (filename, content, ctype)
        headers = dict(extra_headers) if extra_headers else {}
        if self.cfg.rotate_ua and "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        status = None
        try:
            resp = self.session.request(
                method, url, data=fields or None, files=multipart,
                timeout=self.cfg.timeout, allow_redirects=True,
                verify=self.cfg.verify_tls, headers=headers or None, stream=True)
            raw = resp.raw.read(2_000_000, decode_content=True)
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            self._throttle_feedback(status, resp.headers)
            fin = resp.url
            return Response(url, fin, status,
                            {k.lower(): v for k, v in resp.headers.items()},
                            text, resp.elapsed.total_seconds(),
                            [r.headers.get("location", "") for r in resp.history],
                            final_host_in_scope=self.scope.url_in_scope(fin))
        except requests.RequestException as e:
            return Response(url, url, 0, {}, "", 0.0, [], error=type(e).__name__)
        finally:
            self.audit.record(method, url, phase=phase, status=status)

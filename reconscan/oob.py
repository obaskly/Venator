"""Out-of-band (OOB) interaction client — the collaborator for BLIND bugs.

Most high-impact modern bugs are *blind*: the vulnerable server reaches out to an
attacker-controlled host but nothing comes back in the HTTP response. Blind SSRF,
blind OS command injection, blind XXE (external DTD), and blind/stored XSS all
confirm only via an out-of-band callback. This module gives the exploitation
phase a unique callback URL/host per injection and correlates the interactions
that come back.

Two backends, picked automatically:
  * interactsh  — ProjectDiscovery's public OOB infra via the `interactsh-client`
                  binary. Gives DNS *and* HTTP callbacks, supports per-injection
                  correlation in the SUBDOMAIN, fires within seconds. Best path.
  * ngrok       — a local HTTP listener exposed through a reserved ngrok domain.
                  HTTP-only (no DNS), correlation in the URL PATH. Useful as a
                  fallback and — because the domain is persistent — for catching
                  DELAYED blind-XSS callbacks after the scan.

Everything here is callback infrastructure only; it never touches the target.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional

from .utils import log

_ANSI = re.compile(r"\033\[[0-9;]*m")
_OAST = re.compile(r"\b([a-z0-9]{20,}\.oast\.[a-z]+)\b", re.I)
_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


@dataclass
class Interaction:
    protocol: str          # dns | http | smtp | ...
    remote_addr: str
    raw: str               # raw request (DNS question / HTTP request line+headers)
    at: str


def _token() -> str:
    """A DNS-label-safe correlation id (starts with a letter)."""
    return "r" + "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(9))


# ===================================================================== interactsh
class _InteractshBackend:
    """Wraps the `interactsh-client` binary: read the assigned *.oast domain from
    stderr, tail the -json interaction file, correlate by token substring."""

    name = "interactsh"
    dns_capable = True

    def __init__(self, out_file: str):
        self.out_file = out_file
        self.domain = ""
        self.proc: Optional[subprocess.Popen] = None
        self._interactions: List[Interaction] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self, timeout: float = 20.0) -> bool:
        if not shutil.which("interactsh-client"):
            return False
        try:
            open(self.out_file, "w").close()
        except OSError:
            pass
        try:
            self.proc = subprocess.Popen(
                ["interactsh-client", "-json", "-o", self.out_file,
                 "-poll-interval", "5"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except (FileNotFoundError, OSError):
            return False
        # read stderr until the *.oast domain is announced
        deadline = time.time() + timeout
        assert self.proc.stderr is not None
        while time.time() < deadline and self.proc.poll() is None:
            line = self.proc.stderr.readline()
            if not line:
                time.sleep(0.1)
                continue
            m = _OAST.search(_ANSI.sub("", line))
            if m:
                self.domain = m.group(1).lower()
                break
        if not self.domain:
            self.stop()
            return False
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        threading.Thread(target=self._tail, daemon=True).start()
        return True

    def _drain_stderr(self) -> None:
        # keep the pipe from filling (would block the client)
        try:
            assert self.proc and self.proc.stderr
            for _ in self.proc.stderr:
                if self._stop.is_set():
                    return
        except Exception:
            pass

    def _tail(self) -> None:
        pos = 0
        while not self._stop.is_set():
            try:
                if os.path.exists(self.out_file):
                    with open(self.out_file, "r", errors="replace") as fh:
                        fh.seek(pos)
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            self._ingest(line)
                        pos = fh.tell()
            except OSError:
                pass
            time.sleep(1.0)

    def _ingest(self, line: str) -> None:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return
        full = (str(d.get("full-id", "")) + " " + str(d.get("raw-request", ""))).lower()
        it = Interaction(
            protocol=str(d.get("protocol", "")).lower(),
            remote_addr=str(d.get("remote-address", "")),
            raw=full, at=str(d.get("timestamp", "")))
        with self._lock:
            self._interactions.append(it)

    def url(self, token: str, path: str = "") -> str:
        return f"http://{token}.{self.domain}/{path.lstrip('/')}"

    def host(self, token: str) -> str:
        return f"{token}.{self.domain}"

    def hits(self, token: str) -> List[Interaction]:
        t = token.lower()
        with self._lock:
            return [i for i in self._interactions if t in i.raw]

    def stop(self) -> None:
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


# ========================================================================= ngrok
class _NgrokBackend:
    """Local HTTP listener exposed via a reserved ngrok domain. HTTP-only;
    correlation lives in the URL path (a reserved domain can't wildcard
    subdomains). Persistent domain → good for delayed blind-XSS callbacks."""

    name = "ngrok"
    dns_capable = False

    def __init__(self, domain: str):
        self.domain = domain.replace("https://", "").replace("http://", "").strip("/")
        self.proc: Optional[subprocess.Popen] = None
        self.httpd: Optional[ThreadingHTTPServer] = None
        self._hits: List[Interaction] = []
        self._lock = threading.Lock()
        self.port = 0

    def _free_port(self) -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def start(self, timeout: float = 12.0) -> bool:
        if not self.domain or not shutil.which("ngrok"):
            return False
        self.port = self._free_port()
        hits, lock = self._hits, self._lock

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _capture(self):
                body = ""
                try:
                    n = int(self.headers.get("content-length", 0) or 0)
                    if n:
                        body = self.rfile.read(min(n, 4096)).decode("utf-8", "replace")
                except Exception:
                    pass
                raw = (f"{self.command} {self.path} | host={self.headers.get('host','')} "
                       f"| ua={self.headers.get('user-agent','')} | body={body}").lower()
                with lock:
                    hits.append(Interaction("http", self.client_address[0], raw,
                                            time.strftime("%Y-%m-%dT%H:%M:%SZ")))
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.end_headers()
                try:
                    self.wfile.write(b"GIF89a")
                except Exception:
                    pass

            do_GET = _capture
            do_POST = _capture
            do_PUT = _capture
            do_HEAD = _capture

        try:
            self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), _H)
        except OSError:
            return False
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        try:
            self.proc = subprocess.Popen(
                ["ngrok", "http", f"--domain={self.domain}", str(self.port),
                 "--log=stdout"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        except (FileNotFoundError, OSError):
            self.stop()
            return False
        # give the tunnel a moment to come up
        time.sleep(min(timeout, 4.0))
        if self.proc.poll() is not None:   # ngrok died (bad domain/authtoken)
            self.stop()
            return False
        return True

    def url(self, token: str, path: str = "") -> str:
        tail = ("/" + path.lstrip("/")) if path else ""
        return f"https://{self.domain}/{token}{tail}"

    def host(self, token: str) -> str:
        # no per-token DNS on a reserved domain; bare host (weak correlation)
        return self.domain

    def hits(self, token: str) -> List[Interaction]:
        t = token.lower()
        with self._lock:
            return [i for i in self._hits if t in i.raw]

    def stop(self) -> None:
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass


# ======================================================================= facade
class OOBClient:
    """Backend-agnostic collaborator. Modules call new_token()/url()/host(),
    register a Finding factory per planted token, then drain() at the end."""

    def __init__(self, provider: str = "auto", ngrok_domain: str = "",
                 out_file: str = ""):
        self.provider = provider
        self.ngrok_domain = ngrok_domain
        self.out_file = out_file or "/tmp/reconscan_oob.jsonl"
        self.backend = None
        self.enabled = False
        self._registered: Dict[str, Callable[[List[Interaction]], object]] = {}
        self._confirmed: set = set()

    @property
    def domain(self) -> str:
        return self.backend.domain if self.backend else ""

    @property
    def dns_capable(self) -> bool:
        return bool(self.backend and self.backend.dns_capable)

    def start(self) -> bool:
        order = []
        if self.provider in ("auto", "interactsh"):
            order.append(_InteractshBackend(self.out_file))
        if self.provider in ("auto", "ngrok"):
            order.append(_NgrokBackend(self.ngrok_domain))
        if self.provider == "ngrok":
            order = [_NgrokBackend(self.ngrok_domain)]
        elif self.provider == "interactsh":
            order = [_InteractshBackend(self.out_file)]
        for be in order:
            try:
                if be.start():
                    self.backend = be
                    self.enabled = True
                    log("ok", f"OOB collaborator up ({be.name}): {be.domain} "
                              f"(DNS={'yes' if be.dns_capable else 'no'})")
                    return True
            except Exception as e:  # never let OOB setup crash a scan
                log("warn", f"OOB backend {be.name} failed: {type(e).__name__}: {e}")
        log("warn", "OOB collaborator unavailable (interactsh-client/ngrok not usable) "
                    "— blind bug detection disabled")
        return False

    # ---- per-injection helpers (no-ops when disabled) ----
    def new_token(self) -> str:
        return _token()

    def url(self, token: str, path: str = "") -> str:
        return self.backend.url(token, path) if self.enabled else ""

    def host(self, token: str) -> str:
        return self.backend.host(token) if self.enabled else ""

    def register(self, token: str, factory: Callable[[List[Interaction]], object]) -> None:
        """factory(hits) -> Finding, called at drain time if the token fired."""
        if self.enabled:
            self._registered[token] = factory

    def hits(self, token: str) -> List[Interaction]:
        return self.backend.hits(token) if self.enabled else []

    def pending(self) -> int:
        return len(self._registered)

    def drain(self, wait: float = 15.0) -> List[object]:
        """Wait briefly for stragglers, then build Findings for every planted
        token that produced an interaction. Returns confirmed Findings."""
        if not self.enabled or not self._registered:
            return []
        log("info", f"OOB drain: waiting up to {wait:.0f}s for {len(self._registered)} "
                    f"planted callback(s)…")
        deadline = time.time() + wait
        out: List[object] = []
        while True:
            for token, factory in list(self._registered.items()):
                if token in self._confirmed:
                    continue
                hh = self.hits(token)
                if hh:
                    self._confirmed.add(token)
                    try:
                        f = factory(hh)
                        if f:
                            out.append(f)
                    except Exception:
                        pass
            if len(self._confirmed) >= len(self._registered) or time.time() >= deadline:
                break
            time.sleep(2.0)
        fired = len(self._confirmed)
        log("ok" if fired else "info",
            f"OOB drain: {fired}/{len(self._registered)} planted callback(s) fired")
        return out

    def unfired_tokens(self) -> int:
        return len(self._registered) - len(self._confirmed)

    def stop(self) -> None:
        if self.backend:
            try:
                self.backend.stop()
            except Exception:
                pass
        self.enabled = False

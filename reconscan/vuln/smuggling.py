"""HTTP request smuggling / desync detection (CL.TE / TE.CL / TE-obfuscation /
H2C upgrade) via response-timing + protocol-upgrade signals.

Uses the safe timing technique: a desync-crafted request makes the back-end wait
for data that never arrives, so a vulnerable chain delays the response. We only
send the detection probe on our own connection (no second 'victim' request, so we
never poison another user's traffic) and compare timing to a normal request.

Also probes cleartext HTTP/2 (h2c) upgrade: an origin that answers `101 Switching
Protocols` to an `Upgrade: h2c` over HTTP/1.1 behind a front-end that blindly
forwards the upgrade is the modern h2c-smuggling primitive (tunnel an HTTP/2
stream past the edge to reach internal-only routes).

Detection only — a hit is a candidate to confirm manually with Burp/Turbo Intruder.
"""
from __future__ import annotations

import base64
import socket
import ssl
import time
from typing import List
from urllib.parse import urlparse

from ..config import Config
from ..http import Client
from ..utils import log
from ..vuln import Finding


def _send_raw(host: str, port: int, tls: bool, payload: bytes, timeout: float) -> float:
    """Send raw bytes, return seconds until first response byte (or timeout value)."""
    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        sock.recv(64)
        sock.close()
    except (socket.timeout, ssl.SSLError):
        return timeout
    except Exception:
        return -1.0
    return time.monotonic() - start


def _clte(host: str) -> bytes:
    body = "1\r\nA\r\nX"  # back-end (TE) waits for the next chunk -> hang
    return (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding: chunked\r\nContent-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n\r\n{body}").encode()


def _tecl(host: str) -> bytes:
    body = "0\r\n\r\nX"
    return (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n\r\n{body}").encode()


def _te_obfuscated(host: str) -> bytes:
    """TE-header obfuscation: a tab/space-prefixed value many front-ends fail to
    recognise as chunked while the back-end still honours it (classic desync)."""
    body = "1\r\nA\r\nX"
    return (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            f"Transfer-Encoding:\tchunked\r\nContent-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n\r\n{body}").encode()


def _normal(host: str) -> bytes:
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()


def _h2c(host: str) -> bytes:
    """Cleartext-HTTP/2 upgrade request (RFC 7540 §3.2)."""
    settings = base64.urlsafe_b64encode(b"\x00\x00\x00\x04\x00\x00\x00\x00").decode().rstrip("=")
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\nHTTP2-Settings: {settings}\r\n\r\n").encode()


def _raw_response(host: str, port: int, tls: bool, payload: bytes,
                  timeout: float, nbytes: int = 320) -> str:
    """Send raw bytes, return the first `nbytes` of the response as text."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            sock = ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        data = sock.recv(nbytes)
        sock.close()
        return data.decode("latin-1", "replace")
    except Exception:
        return ""


def check(client: Client, service_bases: List[str], cfg: Config) -> List[Finding]:
    if not service_bases:
        return []
    log("info", f"request-smuggling timing probe on {len(service_bases)} host(s)")
    findings: List[Finding] = []
    seen = set()
    to = max(6.0, cfg.timeout)
    for base in service_bases:
        pr = urlparse(base)
        host = pr.hostname
        if not host or host in seen:
            continue
        seen.add(host)
        port = pr.port or (443 if pr.scheme == "https" else 80)
        tls = pr.scheme == "https"

        # --- h2c upgrade probe (one extra request) ---
        resp = _raw_response(host, port, tls, _h2c(host), to)
        client._req_count += 1
        client.audit.record("RAW", f"{base} [h2c upgrade probe]",
                            phase="vuln", tool="smuggling")
        line1 = resp.split("\r\n", 1)[0].lower()
        if "101" in line1 and "switching" in line1 and "h2c" in resp.lower():
            findings.append(Finding(
                title="Cleartext HTTP/2 (h2c) upgrade accepted — smuggling candidate",
                severity="high", category="smuggling", target=base,
                evidence=("the origin answered '101 Switching Protocols' to an "
                          "Upgrade: h2c request. If a front-end proxy forwards this "
                          "upgrade, an attacker tunnels a raw HTTP/2 stream past the "
                          "edge to reach internal/unauthenticated routes. Candidate — "
                          "confirm the front-end forwards the upgrade."),
                recommendation=("Strip/deny the Upgrade: h2c header at the edge; never "
                                "forward client-initiated protocol upgrades to the origin."),
                confidence="tentative"))
            log("vuln", f"[high] h2c upgrade accepted @ {base}")

        baseline = _send_raw(host, port, tls, _normal(host), to)
        if baseline < 0:
            continue
        for name, builder in (("CL.TE", _clte), ("TE.CL", _tecl),
                              ("TE-obfuscation", _te_obfuscated)):
            t = _send_raw(host, port, tls, builder(host), to)
            client._req_count += 1
            client.audit.record("RAW", f"{base} [{name} smuggling probe]",
                                phase="vuln", tool="smuggling")
            # vulnerable signature: probe hangs to timeout while baseline was fast
            if t >= to - 0.5 and baseline < to - 2.0:
                findings.append(Finding(
                    title=f"HTTP request smuggling candidate ({name})",
                    severity="high", category="smuggling", target=base,
                    evidence=f"{name} desync probe hung ~{t:.1f}s vs normal {baseline:.1f}s "
                             "(back-end waited for smuggled body). Candidate — confirm manually.",
                    recommendation=("Confirm with Burp Repeater/Turbo Intruder; do NOT run a "
                                    "victim-poisoning payload on shared infra. Normalize "
                                    "TE/CL handling at the front-end."),
                    confidence="tentative"))
                log("vuln", f"[high] smuggling candidate ({name}) @ {base}")
                break
    return findings

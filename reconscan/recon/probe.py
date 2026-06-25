"""HTTP(S) probing of live hosts: status, title, server header, redirect chain.

Pure-Python via the rate-limited Client (so it's audited + scope-gated).
"""
from __future__ import annotations

import concurrent.futures as cf
import time
from typing import List, Optional, Tuple

from ..audit import AuditLog
from ..config import Config
from ..http import Client, Response
from ..utils import log, title_from_html


def _probe_scheme(client: Client, host: str, scheme: str) -> Tuple[Optional[dict], str]:
    """Return (probe_dict_or_None, error_str). error_str != '' means a
    connection/transport failure (not merely a non-200 response)."""
    url = f"{scheme}://{host}"
    resp = client.get(url, phase="probe", allow_redirects=True)
    if not resp.ok:
        return None, resp.error
    return {
        "url": url,
        "scheme": scheme,
        "final_url": resp.final_url,
        "status": resp.status,
        "title": title_from_html(resp.text),
        "server": resp.headers.get("server", ""),
        "content_type": resp.headers.get("content-type", ""),
        "content_length": len(resp.text),
        "redirect_chain": resp.redirects,
        "redirected_to_https": resp.final_url.startswith("https://"),
        # carry scope flags so downstream phases can drop off-scope redirectors
        # (e.g. mail host -> 3rd-party SSO) and never target assets we don't own.
        "final_host_in_scope": resp.final_host_in_scope,
        "offscope_redirect": resp.offscope_redirect,
        "headers": resp.headers,
        "_body": resp.text,          # consumed by fingerprint/vuln; stripped before JSON
    }, ""


def probe_host(client: Client, host: str) -> Tuple[List[dict], bool]:
    """Probe https+http for one host.

    Returns (results, transient_failure). transient_failure is True when BOTH
    schemes failed with a transport error (connection/timeout) rather than a
    real HTTP response — the signature of a network blip, not a dead host.
    One retry is attempted after a short pause before giving up.
    """
    def _attempt() -> Tuple[List[dict], int]:
        out, errs = [], 0
        for scheme in ("https", "http"):
            res, err = _probe_scheme(client, host, scheme)
            if res:
                out.append(res)
            elif err:
                errs += 1
        return out, errs

    out, errs = _attempt()
    transient = False
    if not out and errs == 2:
        # both schemes errored at transport level — retry once after a pause
        log("warn", f"{host}: both schemes failed ({errs} transport errors), retrying once")
        time.sleep(2.0)
        out, errs = _attempt()
        transient = (not out and errs == 2)

    for r in out:
        log("ok", f"{r['scheme']}://{host} [{r['status']}] "
                  f"{r['server'] or '-'} \"{r['title'][:60]}\"")
    return out, transient


def probe(client: Client, live_hosts: List[str], cfg: Config) -> Tuple[List[dict], List[str]]:
    """Returns (probe_results, failed_hosts). failed_hosts lists live hosts that
    yielded no HTTP service due to transport errors (surfaced as a warning)."""
    log("step", f"HTTP probing ({len(live_hosts)} hosts)")
    results: List[dict] = []
    failed: List[str] = []
    # Concurrency is safe: the global RateLimiter serializes actual requests.
    with cf.ThreadPoolExecutor(max_workers=max(2, cfg.threads)) as ex:
        futures = {ex.submit(probe_host, client, h): h for h in live_hosts}
        for fut in cf.as_completed(futures):
            host = futures[fut]
            res, transient = fut.result()
            results.extend(res)
            if transient:
                failed.append(host)
    return results, failed

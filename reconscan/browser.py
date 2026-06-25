"""Headless-browser phase — render JavaScript, then see what static HTTP can't.

Three jobs, one Chromium session:

  1. SPA surface expansion — the static crawler goes shallow on React/Angular/Vue
     apps (routes live behind the `#` and XHRs fire only after render). We render
     each seed, let the app boot, and capture every in-scope network request the
     page actually makes (XHR/fetch/document/script) plus the post-render DOM
     links + forms. All of it is merged back into the surface the later phases eat.

  2. DOM-based XSS confirmation — EXECUTION is the oracle, so it's zero-FP. An init
     script defines a unique sentinel (`window.__rcxss`) and hooks alert/confirm/
     prompt; we navigate parameter/fragment sinks with a payload that calls the
     sentinel, then read it back. If the token comes back, the payload *ran* in a
     real browser — confirmed DOM XSS, no guessing from source→sink co-occurrence.

  3. Scope containment — every browser request is routed through a guard that
     ABORTS anything off-scope, so the headless engine can't wander out of bounds.

Optional + self-disabling: if Playwright (or a Chromium/Chrome) isn't present the
phase logs once and returns nothing. Navigation is audited and politeness-spaced.
"""
from __future__ import annotations

import random
import string
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from .config import Config
from .utils import Scope, dedup_keep_order, log
from .vuln import Finding

# sinks worth firing: classic HTML-injection + hash/innerHTML DOM sinks.
_PAYLOAD_TEMPLATES = [
    '"><img src=x onerror=__rcxss(\'{T}\')>',
    "'><svg onload=__rcxss('{T}')>",
    '"><script>__rcxss(\'{T}\')</script>',
]
_HASH_TEMPLATES = [
    '<img src=x onerror=__rcxss(\'{T}\')>',
    '<svg onload=__rcxss(\'{T}\')>',
]

_INIT_JS = """
window.__rc_hits = [];
window.__rcxss = function(t){ try{ window.__rc_hits.push(String(t)); }catch(e){} };
['alert','confirm','prompt'].forEach(function(fn){
  try{ var o=window[fn]; window[fn]=function(a){ window.__rc_hits.push('alert:'+a); return o&&o(a);}; }catch(e){}
});
"""

# request kinds worth keeping as surface: the app's real data calls (XHR/fetch/
# websocket) + the documents it navigates to. Static assets are dropped as noise.
_CAPTURE_TYPES = {"xhr", "fetch", "websocket", "document"}
_STATIC_RT = {"image", "stylesheet", "font", "media", "manifest", "other"}


_STATIC_EXT = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".ico", ".webp", ".woff", ".woff2", ".ttf", ".map", ".wasm")


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(_STATIC_EXT)


def _tok(n: int = 10) -> str:
    return "rc" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _set_param(url: str, name: str, value: str) -> str:
    pr = urlparse(url)
    qs = parse_qsl(pr.query, keep_blank_values=True)
    qs = [(k, value if k == name else v) for k, v in qs]
    return urlunparse(pr._replace(query=urlencode(qs)))


def _launch(p):
    try:
        return p.chromium.launch(headless=True, args=["--no-sandbox"])
    except Exception:
        return p.chromium.launch(headless=True, channel="chrome",
                                 args=["--no-sandbox"])


def run(scope: Scope, seeds: List[str], param_urls: List[str], cfg: Config,
        audit=None) -> Tuple[List[Finding], Dict[str, object]]:
    if not getattr(cfg, "do_browser", True):
        return [], {"skipped": "disabled"}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("info", "browser phase skipped: playwright not installed "
                    "(`pip install playwright`)")
        return [], {"skipped": "no-playwright"}

    log("step", "Headless browser (SPA render + DOM-XSS confirm)")
    max_pages = max(1, getattr(cfg, "browser_max_pages", 20))
    findings: List[Finding] = []
    captured: set = set()
    rendered = 0
    domxss_tests = 0
    post_links: List[str] = []
    post_forms: List[dict] = []
    spacing = max(0.0, getattr(cfg, "min_interval", 0.0))

    try:
        with sync_playwright() as p:
            try:
                browser = _launch(p)
            except Exception as e:
                log("warn", f"browser phase skipped: cannot launch Chromium ({e})")
                return [], {"skipped": "no-chromium"}
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=getattr(cfg, "user_agent", None) or None)
            ctx.set_default_navigation_timeout(int(cfg.timeout * 1000))
            ctx.add_init_script(_INIT_JS)

            # --- scope containment + endpoint capture on EVERY request ---
            def _route(route):
                req = route.request
                host = urlparse(req.url).netloc
                if scope.host_in_scope(host):
                    rt = req.resource_type
                    if rt in _CAPTURE_TYPES and not _is_static(req.url):
                        captured.add(req.url)
                    elif "?" in req.url and rt not in _STATIC_RT:
                        captured.add(req.url)
                    route.continue_()
                else:
                    if audit:
                        audit.record(req.method, req.url, phase="browser",
                                     note="BLOCKED_OUT_OF_SCOPE")
                    route.abort()
            ctx.route("**/*", _route)
            page = ctx.new_page()

            def _goto(url: str) -> bool:
                if not scope.url_in_scope(url):
                    return False
                if audit:
                    audit.record("GET", url, phase="browser")
                try:
                    page.goto(url, wait_until="domcontentloaded")
                    try:                          # let late XHRs / hash routers fire
                        page.wait_for_load_state("networkidle", timeout=4000)
                    except Exception:
                        page.wait_for_timeout(1200)
                    return True
                except Exception:
                    return False

            # --- pass 1: render seeds, harvest post-render DOM + network ---
            for url in dedup_keep_order(seeds)[:max_pages]:
                if not _goto(url):
                    continue
                rendered += 1
                try:
                    links = page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)") or []
                    post_links += [u for u in links if scope.url_in_scope(u)]
                    forms = page.eval_on_selector_all(
                        "form",
                        "els => els.map(f => ({action: f.action, method: (f.method||'get'),"
                        " fields: Array.from(f.querySelectorAll('input,textarea,select'))"
                        ".map(i => ({name: i.name||i.id||'', type: i.type||'text'}))}))") or []
                    for f in forms:
                        if f.get("action") and scope.url_in_scope(f["action"]):
                            # normalize to the same schema _parse_forms emits so the
                            # surface dedup + injectors treat both producers alike
                            f["method"] = (f.get("method") or "GET").upper()
                            f["fields"] = [{"name": x.get("name", ""),
                                            "type": (x.get("type") or "text").lower(),
                                            "value": ""}
                                           for x in f.get("fields", []) if x.get("name")]
                            if f["fields"]:
                                post_forms.append(f)
                except Exception:
                    pass
                if spacing:
                    time.sleep(spacing)

            # --- pass 2: execution-based DOM-XSS confirmation ---
            dx_targets = [u for u in dedup_keep_order(param_urls) if "?" in u][:max_pages]
            for url in dx_targets:
                if domxss_tests >= max_pages * 2:
                    break
                names = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
                if not names:
                    continue
                finding, n = _probe_domxss(page, scope, url, names[0], spacing)
                domxss_tests += n
                if finding:
                    findings.append(finding)

            # --- pass 3: fragment (#) DOM-XSS on the seeds themselves ---
            for url in dedup_keep_order(seeds)[:max_pages // 2 or 1]:
                if not scope.url_in_scope(url):
                    continue
                for tpl in _HASH_TEMPLATES:
                    t = _tok()
                    payload = url.split("#")[0] + "#" + tpl.format(T=t)
                    if audit:
                        audit.record("GET", payload, phase="browser")
                    try:
                        page.goto(payload, wait_until="load")
                        page.wait_for_timeout(500)
                        hits = page.evaluate("window.__rc_hits || []")
                    except Exception:
                        continue
                    domxss_tests += 1
                    if any(t in h for h in hits):
                        findings.append(_domxss_finding(payload, "location.hash"))
                        break
                if spacing:
                    time.sleep(spacing)

            ctx.close()
            browser.close()
    except Exception as e:
        log("warn", f"browser phase aborted: {e}")

    urls = dedup_keep_order(post_links + sorted(captured))
    forms = _dedup_forms(post_forms)
    if findings:
        log("vuln", f"browser: {len(findings)} confirmed DOM-XSS")
    log("ok", f"browser: {rendered} page(s) rendered, {len(urls)} URL(s) "
             f"({len(captured)} via network), {len(forms)} form(s), "
             f"{domxss_tests} DOM-XSS test(s)")
    return findings, {
        "rendered": rendered, "urls": urls, "forms": forms,
        "domxss_tests": domxss_tests, "network_endpoints": len(captured),
    }


def _probe_domxss(page, scope, url, name, spacing) -> Tuple[object, int]:
    tests = 0
    for tpl in _PAYLOAD_TEMPLATES:
        t = _tok()
        payload_url = _set_param(url, name, tpl.format(T=t))
        if not scope.url_in_scope(payload_url):
            return None, tests
        try:
            page.goto(payload_url, wait_until="load")
            page.wait_for_timeout(500)
            hits = page.evaluate("window.__rc_hits || []")
        except Exception:
            continue
        tests += 1
        if any(t in h for h in hits):
            return _domxss_finding(payload_url, f"parameter `{name}`"), tests
    if spacing:
        time.sleep(spacing)
    return None, tests


def _domxss_finding(url: str, sink: str) -> Finding:
    return Finding(
        title="DOM-based XSS confirmed (payload executed in headless browser)",
        severity="high", category="xss", target=url,
        evidence=f"a crafted payload delivered via {sink} executed JavaScript in a "
                 f"real rendered page (the sentinel callback fired). This is "
                 f"execution-confirmed, not a source→sink guess.",
        recommendation=("Encode/clean untrusted data before it reaches a DOM sink "
                        "(innerHTML/document.write/eval/hash routers). Prefer "
                        "textContent and a strict CSP that forbids inline script."),
        confidence="confirmed",
        poc=f"open in a browser: {url}")


def _dedup_forms(forms: List[dict]) -> List[dict]:
    best: Dict[tuple, dict] = {}
    for f in forms:
        pr = urlparse(f.get("action", ""))
        key = (pr.netloc, pr.path, (f.get("method") or "get").lower(),
               tuple(sorted(x.get("name", "") for x in f.get("fields", []))))
        best.setdefault(key, f)
    return list(best.values())

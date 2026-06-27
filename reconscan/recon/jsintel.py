"""JavaScript intelligence: pull referenced JS, mine endpoints + leaked secrets.

This is high-signal recon for bug bounty — modern apps leak API routes, internal
hostnames, and occasionally live credentials inside bundled JavaScript. All
strictly non-destructive: GET the scripts (rate-limited + scope-gated), regex the
text, report. Secrets are reported, never used.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..config import Config
from ..data import (DOM_SINKS, DOM_SOURCES, ENDPOINT_PATTERNS, SECRET_PATTERNS,
                    SECRET_PLACEHOLDERS)
from ..http import Client
from ..utils import Scope, dedup_keep_order, log
from ..vuln import Finding

_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.I)
# Next.js / webpack often inline a manifest of chunk paths.
_CHUNK = re.compile(r"""['"]((?:/_next/static|/static/js|/assets|/js)/[A-Za-z0-9_\-./]+\.js)['"]""")
_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.I)


def _looks_placeholder(val: str) -> bool:
    low = val.lower()
    return any(p in low for p in SECRET_PLACEHOLDERS)


def _collect_script_urls(probe: dict, scope: Scope) -> List[str]:
    base = probe.get("final_url") or probe.get("url")
    body = probe.get("_body", "") or ""
    urls: List[str] = []
    for m in _SCRIPT_SRC.finditer(body):
        urls.append(urljoin(base, m.group(1)))
    for m in _CHUNK.finditer(body):
        urls.append(urljoin(base, m.group(1)))
    # keep only in-scope, .js, deduped
    out = []
    for u in dedup_keep_order(urls):
        p = urlparse(u)
        if not p.path.endswith(".js"):
            continue
        if scope.host_in_scope(p.netloc):
            out.append(u)
    return out


def _scan_secrets(text: str, source: str, sink: list = None) -> List[Finding]:
    findings: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()
    for label, sev, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if _looks_placeholder(val):
                continue
            key = (label, val)
            if key in seen:
                continue
            seen.add(key)
            # stash the RAW value (off-report) so the opt-in secret-validation
            # phase can verify it live; the Finding itself only ever stores a mask.
            if sink is not None:
                sink.append((label, val, source))
            masked = val[:4] + "…" + val[-4:] if len(val) > 12 else val[:3] + "…"
            findings.append(Finding(
                title=f"Possible {label} in JavaScript",
                severity=sev, category="secret", target=source,
                evidence=f"matched `{label}` (masked: {masked}) in {source}",
                recommendation=("The secret-validation phase replays this read-only "
                                "against its issuer API to confirm whether it is LIVE "
                                "(a confirmed live key is upgraded to a high finding). "
                                "Rotate it and remove it from the client bundle."),
                confidence="tentative"))
    return findings


def _recover_sourcemap(client: Client, js_url: str, js_text: str,
                       scope: Scope) -> tuple:
    """If a .js ships (or references) a source map, fetch it and reconstruct the
    ORIGINAL source from sourcesContent. Minified bundles hide secrets/routes
    that the readable source exposes. Returns (recovered_text, n_sources, map_url)."""
    m = _SOURCEMAP.search(js_text or "")
    candidates = []
    if m:
        candidates.append(urljoin(js_url, m.group(1)))
    candidates.append(js_url + ".map")
    for map_url in dedup_keep_order(candidates):
        p = urlparse(map_url)
        if p.scheme not in ("http", "https") or not scope.host_in_scope(p.netloc):
            continue
        resp = client.get(map_url, phase="jsintel")
        if not resp.ok or resp.status != 200:
            continue
        try:
            import json
            doc = json.loads(resp.text)
        except Exception:
            continue
        contents = doc.get("sourcesContent") or []
        recovered = "\n".join(c for c in contents if isinstance(c, str))
        if recovered:
            return recovered, len([c for c in contents if c]), map_url
    return "", 0, ""


# a real source->sink data flow keeps the tainted read NEAR the dangerous write.
# Requiring proximity kills the dominant false positive: a large minified framework
# bundle where `location.href` and `innerHTML` merely co-occur in unrelated code.
_DOM_PROXIMITY = 120


def _is_minified(text: str) -> bool:
    """Minified/bundled scripts pack unrelated statements densely, so even a tight
    proximity window catches co-occurring source/sink tokens that aren't a real
    flow. The execution-confirmed headless-browser phase is the authoritative
    DOM-XSS check for these; here we only mine READABLE scripts where proximity is
    meaningful. Heuristic: any very long line == minified."""
    if not text:
        return True
    return any(len(line) > 1000 for line in text.splitlines())


def _nearest_source_sink(low: str):
    """Smallest gap between any DOM source occurrence and any DOM sink occurrence.
    Returns (distance, source, sink) or None."""
    src_pos = [(m.start(), s) for s in DOM_SOURCES for m in re.finditer(re.escape(s), low)]
    if not src_pos:
        return None
    sink_pos = [(m.start(), k) for k in DOM_SINKS for m in re.finditer(re.escape(k), low)]
    if not sink_pos:
        return None
    sink_pos.sort()
    starts = [p for p, _ in sink_pos]
    import bisect
    best = None
    for sp, s in src_pos:
        i = bisect.bisect_left(starts, sp)
        for j in (i - 1, i):                    # nearest sink before/after the source
            if 0 <= j < len(sink_pos):
                d = abs(sink_pos[j][0] - sp)
                if best is None or d < best[0]:
                    best = (d, s, sink_pos[j][1])
    return best


def _dom_xss_leads(text: str, source: str) -> List[Finding]:
    """A tainted DOM source flowing toward a dangerous sink WITHIN the same code
    region = a DOM-XSS lead. Proximity-gated so file-wide co-occurrence in minified
    bundles doesn't false-positive (the execution-confirmed browser phase is the
    authoritative DOM-XSS check; this is only a manual-review lead)."""
    if _is_minified(text):
        return []
    low = (text or "").lower()
    best = _nearest_source_sink(low)
    if not best or best[0] > _DOM_PROXIMITY:
        return []
    dist, src_hit, sink_hit = best
    return [Finding(
        title="Potential DOM-based XSS (source -> sink in client script)",
        severity="medium", category="xss", target=source,
        evidence=f"a tainted source ({src_hit}) and a dangerous sink ({sink_hit}) "
                 f"appear within {dist} chars of each other — a plausible data flow.",
        recommendation=("MANUAL: confirm the source reaches the sink unsanitized and build "
                        "a PoC (e.g. via location.hash). Use safe DOM APIs / output encoding."),
        confidence="tentative")]


def _extract_endpoints(text: str, scope: Scope, base: str) -> List[str]:
    found: List[str] = []
    for rx in ENDPOINT_PATTERNS:
        for m in rx.finditer(text):
            ep = m.group(1)
            if not ep or ep.startswith(("data:", "mailto:", "javascript:", "#")):
                continue
            if ep.startswith("//"):
                ep = "https:" + ep
            if ep.startswith("http"):
                if scope.url_in_scope(ep):
                    found.append(ep)
            elif ep.startswith("/"):
                found.append(ep)
    return dedup_keep_order(found)


def analyze(client: Client, scope: Scope, probes: List[dict], cfg: Config,
            max_files: int = 25,
            secret_sink: list = None) -> Tuple[List[Finding], Dict[str, object]]:
    """Returns (findings, summary). summary has js_files, endpoints, secrets_count.

    `secret_sink`, if given, collects raw (label, value, source) tuples for the
    opt-in live secret-validation phase. Raw values never enter `summary`/report.
    """
    log("step", "JS intelligence (endpoint + secret mining)")
    script_urls: List[str] = []
    for p in probes:
        script_urls.extend(_collect_script_urls(p, scope))
    script_urls = dedup_keep_order(script_urls)[:max_files]

    findings: List[Finding] = []
    endpoints: List[str] = []

    # inline scripts in the HTML bodies too
    for p in probes:
        body = p.get("_body", "") or ""
        src = p.get("final_url") or p.get("url")
        findings += _scan_secrets(body, src, secret_sink)
        endpoints += _extract_endpoints(body, scope, src)
        if cfg.do_sourcemap:
            findings += _dom_xss_leads(body, src)

    fetched = 0
    maps_recovered = 0
    for u in script_urls:
        resp = client.get(u, phase="jsintel")
        if not resp.ok:
            continue
        fetched += 1
        findings += _scan_secrets(resp.text, u, secret_sink)
        endpoints += _extract_endpoints(resp.text, scope, u)
        if cfg.do_sourcemap:
            findings += _dom_xss_leads(resp.text, u)
            recovered, n_src, map_url = _recover_sourcemap(client, u, resp.text, scope)
            if recovered:
                maps_recovered += 1
                # deeper mine the readable original source
                findings += _scan_secrets(recovered, map_url, secret_sink)
                endpoints += _extract_endpoints(recovered, scope, map_url)
                findings += _dom_xss_leads(recovered, map_url)
                findings.append(Finding(
                    title="JavaScript source map exposed (original source recovered)",
                    severity="low", category="misconfig", target=map_url,
                    evidence=f"{map_url} returned {n_src} original source file(s) via "
                             "sourcesContent — reconstructed readable source for deeper mining.",
                    recommendation=("Don't ship source maps to production; they reveal internal "
                                    "code, routes, and sometimes secrets. Strip or restrict them."),
                    confidence="firm"))
                log("ok", f"recovered source map: {map_url} ({n_src} sources)")

    endpoints = dedup_keep_order(endpoints)
    if findings:
        log("vuln", f"JS intel: {len(findings)} finding(s) across {fetched} script(s)")
    log("ok", f"JS intel: {fetched} scripts analyzed, {maps_recovered} source map(s) "
             f"recovered, {len(endpoints)} endpoints extracted")
    summary = {
        "scripts_analyzed": fetched,
        "source_maps_recovered": maps_recovered,
        "endpoints": endpoints,
        "secret_candidates": sum(1 for f in findings if f.category == "secret"),
    }
    return findings, summary

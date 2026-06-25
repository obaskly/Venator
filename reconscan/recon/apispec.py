"""OpenAPI / Swagger ingestion.

A published API spec is a free, precise map of the attack surface: every path,
method, and query parameter the backend accepts. When one is reachable we parse
it and hand the resolved endpoint+param URLs to the exploitation phase (so SQLi /
IDOR / SSRF / mass-assignment run against the *documented* surface, not just what
we could guess), and flag the exposure itself.

Read-only: GET the spec, parse, report. JSON specs always; YAML if PyYAML is
installed.
"""
from __future__ import annotations

import json
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

from ..config import Config
from ..data import OPENAPI_PATHS
from ..http import Client
from ..utils import dedup_keep_order, log
from ..vuln import Finding

_MAX_URLS = 80


def _load(text: str):
    text = (text or "").strip()
    if not text:
        return None
    if text[0] in "{[":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    try:
        import yaml  # optional
        return yaml.safe_load(text)
    except Exception:
        return None


def _is_spec(doc) -> bool:
    return isinstance(doc, dict) and (
        "swagger" in doc or "openapi" in doc) and isinstance(doc.get("paths"), dict)


def _bases(doc, spec_url: str, scope) -> List[str]:
    """Resolve the server base URL(s) the spec's paths hang off — in scope only."""
    out: List[str] = []
    pr = urlparse(spec_url)
    svc = f"{pr.scheme}://{pr.netloc}"
    if "openapi" in doc:  # OpenAPI 3.x
        for srv in (doc.get("servers") or []):
            u = (srv or {}).get("url", "")
            if not u:
                continue
            full = u if u.startswith("http") else urljoin(svc + "/", u.lstrip("/"))
            if scope.url_in_scope(full):
                out.append(full.rstrip("/"))
    else:                 # Swagger 2.0
        schemes = doc.get("schemes") or [pr.scheme]
        host = doc.get("host") or pr.netloc
        basep = doc.get("basePath") or ""
        for sch in schemes:
            full = f"{sch}://{host}{basep}".rstrip("/")
            if scope.url_in_scope(full):
                out.append(full)
    if not out:
        out.append(svc)
    return dedup_keep_order(out)


def _op_params(op: dict, shared: list) -> List[str]:
    names = []
    for prm in (shared or []) + (op.get("parameters") or []):
        if isinstance(prm, dict) and prm.get("in") == "query" and prm.get("name"):
            names.append(prm["name"])
    return names


def _spec_urls(doc, base: str, scope) -> List[str]:
    urls: List[str] = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        concrete = path.replace("}", "").replace("{", "")  # {id} -> id placeholder
        # fill templated segments with 1 so the URL is requestable
        segs = []
        for s in path.strip("/").split("/"):
            segs.append("1" if (s.startswith("{") and s.endswith("}")) else s)
        full = base.rstrip("/") + "/" + "/".join(segs)
        if not scope.url_in_scope(full):
            continue
        shared = item.get("parameters") or []
        qparams: List[str] = []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch") \
                    or not isinstance(op, dict):
                continue
            qparams += _op_params(op, shared)
        qparams = dedup_keep_order(qparams)
        if qparams:
            urls.append(full + "?" + "&".join(f"{q}=1" for q in qparams))
        else:
            urls.append(full)
    return dedup_keep_order(urls)


def discover(client: Client, services: List[dict], scope, cfg: Config
             ) -> Tuple[List[Finding], List[str]]:
    if not cfg.do_apispec:
        return [], []
    findings: List[Finding] = []
    all_urls: List[str] = []
    seen_specs = set()
    for s in services:
        base = s["base_url"].rstrip("/")
        for path in OPENAPI_PATHS:
            if client.over_budget():
                break
            url = base + path
            r = client.get(url, phase="apispec")
            if not r.ok or r.status != 200:
                continue
            doc = _load(r.text)
            if not _is_spec(doc):
                continue
            sig = (urlparse(url).netloc, len(doc.get("paths", {})))
            if sig in seen_specs:
                continue
            seen_specs.add(sig)
            title = (doc.get("info") or {}).get("title", "API")
            n_paths = len(doc.get("paths") or {})
            urls: List[str] = []
            for b in _bases(doc, url, scope):
                urls += _spec_urls(doc, b, scope)
            urls = dedup_keep_order(urls)[:_MAX_URLS]
            all_urls += urls
            findings.append(Finding(
                title="OpenAPI/Swagger specification exposed",
                severity="low", category="misconfig", target=url,
                evidence=f"reachable API spec '{title}' documents {n_paths} path(s); "
                         f"{len(urls)} endpoint URL(s) folded into the exploitation surface.",
                recommendation=("Confirm the spec should be public. It hands an attacker a "
                                "complete map of endpoints + parameters — prime targets for "
                                "IDOR / mass-assignment / injection. Restrict if internal."),
                confidence="firm"))
            log("ok", f"OpenAPI spec @ {url}: {n_paths} paths, {len(urls)} surface URL(s)")
    return findings, dedup_keep_order(all_urls)

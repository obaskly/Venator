"""URL / parameter attack-surface classification (gf-style).

Recon dumps a flat list of URLs; a hunter wants to know *which* parameters are
worth attacking first. This tags every discovered URL parameter (and interesting
file path) by the bug class its NAME historically correlates with — the same idea
as tomnomnom's ``gf`` pattern packs — so the report leads with a ranked parameter
attack-surface map and the scorer boosts findings that sit on a high-value param.

Pure pattern matching over already-discovered URLs: it issues NO new requests.
"""
from __future__ import annotations

from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qsl

from ..utils import is_catch_all_artifact
from ..vuln import Finding

# param-name -> bug class. Mirrors the well-known gf pattern packs (tomnomnom /
# 1ndianl33t Gf-Patterns), trimmed to the highest-signal names per class.
_CLASS_PARAMS: Dict[str, Set[str]] = {
    "sqli": {"id", "select", "report", "role", "update", "query", "user", "name",
             "sort", "where", "search", "params", "process", "row", "view",
             "table", "from", "sel", "results", "fetch", "order", "keyword",
             "column", "field", "delete", "string", "number", "filter", "uid",
             "pid", "cat", "category"},
    "xss": {"q", "s", "search", "id", "action", "keyword", "query", "keywords",
            "year", "email", "p", "jsonp", "page", "name", "title", "message",
            "comment", "body", "content", "text", "value", "input", "data",
            "ref", "callback"},
    "ssrf": {"url", "uri", "dest", "destination", "redirect", "redirecturl",
             "callback", "feed", "host", "port", "to", "out", "target", "site",
             "html", "file", "path", "src", "source", "u", "proxy", "fetch",
             "resource", "domain", "page", "load", "img", "image", "imageurl",
             "next", "continue", "reference", "open", "window"},
    "lfi": {"file", "document", "folder", "root", "path", "pg", "style", "pdf",
            "template", "php_path", "doc", "page", "name", "cat", "dir", "action",
            "board", "detail", "download", "prefix", "include", "inc", "locate",
            "show", "site", "type", "view", "content", "layout", "mod", "conf",
            "filename", "filepath"},
    "rce": {"cmd", "exec", "command", "execute", "ping", "jump", "code", "reg",
            "do", "func", "arg", "option", "load", "process", "step", "read",
            "function", "req", "feature", "exe", "module", "payload", "run",
            "print", "daemon", "upload", "dir", "download", "log", "ip", "cli",
            "system"},
    "redirect": {"url", "redirect", "redirect_to", "redirecturl", "redirect_uri",
                 "return", "returnurl", "return_url", "returnto", "next", "dest",
                 "destination", "continue", "goto", "out", "to", "image_url",
                 "go", "target", "rurl", "callback", "checkout_url", "r", "u",
                 "link", "redir", "forward", "success", "cancel", "back",
                 "backurl", "relaystate"},
    "ssti": {"name", "q", "search", "id", "action", "page", "keyword", "query",
             "title", "view", "template", "preview", "message", "body",
             "content", "text"},
    "idor": {"id", "user", "user_id", "userid", "account", "account_id", "number",
             "order", "order_id", "no", "doc", "key", "email", "group", "profile",
             "edit", "report", "uid", "pid", "customer", "cid", "invoice",
             "ticket", "object", "item"},
    "debug": {"debug", "test", "dbg", "env", "environment", "console", "source",
              "verbose", "trace", "stack", "mode", "feature", "beta"},
    "secret": {"token", "key", "secret", "password", "passwd", "pwd", "apikey",
               "api_key", "access_token", "auth", "authorization", "jwt",
               "session", "sessionid", "client_secret", "private_key",
               "signature", "sig", "hash", "nonce"},
}

# classes whose param hits justify a priority boost for findings on that URL
_HOT_CLASSES = {"sqli", "ssrf", "rce", "lfi", "ssti", "redirect", "idor"}

_SENS_EXT = (".json", ".xml", ".sql", ".bak", ".backup", ".config", ".conf",
             ".yml", ".yaml", ".env", ".log", ".db", ".sqlite", ".zip", ".tar",
             ".gz", ".tgz", ".swp", ".old", ".orig", ".save", ".csv", ".ini",
             ".pem", ".key", ".p12", ".ds_store", ".inc", ".tmp")

_SENS_PATH = ("/admin", "/internal", "/debug", "/backup", "/config", "/setup",
              "/install", "phpinfo", "/actuator", "/console", "/.git", "/graphql",
              "/swagger", "/openapi", "/api-docs", "/metrics", "/dashboard",
              "/wp-admin", "/jenkins")

# static assets are never an "interesting file" even under a sensitive dir — a
# soft-404 SPA serves bundle chunks at /.git/chunk-X.js etc., pure noise.
_STATIC_EXT = (".js", ".css", ".map", ".ico", ".png", ".jpg", ".jpeg", ".svg",
               ".gif", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4")

# transport / dev endpoints that soft-404 hosts glue onto every path — noise
_TRANSPORT = ("/socket.io/", "/sockjs", "/engine.io", "__webpack_hmr",
              "hot-update", "/__nextjs")


def _iter_urls(recon: dict) -> List[str]:
    urls: List[str] = []
    for ep in recon.get("endpoints", []):
        if ep.get("base_url"):
            urls.append(ep["base_url"])
        for d in ep.get("discovered", []):
            if isinstance(d, dict) and d.get("url"):
                urls.append(d["url"])
        urls += [u for u in ep.get("sitemap", []) if u]
    js = recon.get("jsintel") or {}
    urls += [e for e in js.get("endpoints", []) if isinstance(e, str)]
    wb = recon.get("wayback") or {}
    urls += [u for u in (wb.get("juicy_urls") or []) if isinstance(u, str)]
    return urls


def _norm(pr) -> str:
    """scheme-less netloc+path key (so http/https collapse for boost matching)."""
    return f"{pr.netloc}{pr.path}"


def classify(recon: dict, max_hotspots: int = 60
             ) -> Tuple[dict, Set[str], List[Finding]]:
    """Return (summary, hot_targets, findings).

    hot_targets is a set of scheme-less ``netloc+path`` keys carrying a
    high-value classified parameter — the scorer boosts findings on them.
    """
    by_class: Dict[str, Set[str]] = {k: set() for k in _CLASS_PARAMS}
    hotspots: Dict[str, dict] = {}
    files: Set[str] = set()
    hot_targets: Set[str] = set()

    for raw in _iter_urls(recon):
        if is_catch_all_artifact(raw) or any(t in raw.lower() for t in _TRANSPORT):
            continue
        pr = urlparse(raw)
        low_path = (pr.path or "").lower()
        is_static = any(low_path.endswith(e) for e in _STATIC_EXT)
        if not is_static and (any(low_path.endswith(e) for e in _SENS_EXT)
                              or any(seg in low_path for seg in _SENS_PATH)):
            files.add(f"{pr.scheme}://{pr.netloc}{pr.path}" if pr.scheme else raw)
        for pname, _ in parse_qsl(pr.query, keep_blank_values=True):
            pl = pname.lower()
            classes = [c for c, names in _CLASS_PARAMS.items() if pl in names]
            if not classes:
                continue
            for c in classes:
                by_class[c].add(pl)
            key = f"{_norm(pr)}?{pl}"
            ent = hotspots.setdefault(
                key, {"url": f"{pr.scheme}://{pr.netloc}{pr.path}",
                      "param": pname, "classes": set()})
            ent["classes"].update(classes)
            if _HOT_CLASSES.intersection(classes):
                hot_targets.add(_norm(pr))

    counts = {c: len(v) for c, v in by_class.items() if v}
    hs_list = sorted(hotspots.values(), key=lambda h: -len(h["classes"]))[:max_hotspots]
    for h in hs_list:
        h["classes"] = sorted(h["classes"])
    summary = {
        "params_classified": len(hotspots),
        "by_class": counts,
        "hotspots": hs_list,
        "interesting_files": sorted(files)[:60],
    }

    findings: List[Finding] = []
    if hotspots or files:
        top = ", ".join(f"{c}:{n}" for c, n in
                        sorted(counts.items(), key=lambda kv: -kv[1]))
        ev = [f"{h['param']} ({'/'.join(h['classes'])}) @ {h['url']}"
              for h in hs_list[:15]]
        if files:
            ev.append("interesting files: " + ", ".join(sorted(files)[:10]))
        tgt = hs_list[0]["url"] if hs_list else (sorted(files)[0] if files else "-")
        findings.append(Finding(
            title="Parameter attack-surface map",
            severity="info", category="recon", target=tgt,
            evidence=(f"{len(hotspots)} parameter(s) classified by likely bug class "
                      f"[{top}]. Top candidates:\n  " + "\n  ".join(ev)),
            recommendation=("Prioritise testing these parameters by their tagged "
                            "class (SQLi/SSRF/LFI/redirect/SSTI/IDOR). This map "
                            "issues no requests; it ranks existing surface."),
            confidence="firm"))
    return summary, hot_targets, findings

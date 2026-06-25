"""Common misconfiguration detection (non-destructive, GET/HEAD only):

  * exposed sensitive files/paths (.git, .env, server-status, actuator, ...)
  * directory listing enabled ("Index of /")
  * verbose error messages / stack traces on a benign 404
"""
from __future__ import annotations

import re
import secrets
from typing import List
from urllib.parse import urljoin, urlparse

from ..data import SENSITIVE_PATHS
from ..http import Client
from ..utils import dedup_keep_order, log
from . import Finding

# Signatures of framework stack traces / verbose errors.
STACKTRACE_SIGNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java stack trace"),
    (r"Warning: .*? in .*? on line \d+", "PHP warning"),
    (r"Fatal error: .*? in .*? on line \d+", "PHP fatal error"),
    (r"<b>(?:Notice|Warning|Deprecated)</b>:", "PHP error block"),
    (r"System\.[\w.]+Exception", ".NET exception"),
    (r"org\.springframework\.[\w.]+Exception", "Spring exception"),
    (r"ORA-\d{5}", "Oracle DB error"),
    (r"SQLSTATE\[", "SQL error (PDO)"),
    (r"You have an error in your SQL syntax", "MySQL error"),
    (r"psql: error|PG::\w+Error", "PostgreSQL error"),
    (r"Microsoft OLE DB Provider for", "MSSQL/OLEDB error"),
    (r"DEBUG = True|django\.core\.exceptions|Werkzeug Debugger", "Debug mode enabled"),
]

DIR_LISTING_SIGNS = [
    r"<title>Index of /", r"<h1>Index of /",
    r"Directory listing for /",
    # Express/Node `serve-index` (e.g. OWASP Juice Shop /ftp) + other variants
    r"<title>listing directory /", r"<h1>listing directory /",
    r"<title>Directory Listing",
]


def _status_indicates_present(status: int) -> bool:
    # treat 200/206/401/403 as "exists / sensitive" — 401/403 still proves the
    # path is recognised by the server. 301/302 handled by caller via location.
    return status in (200, 206, 401, 403)


def _catch_all_baseline(client: Client, base_url: str) -> dict:
    """What a guaranteed-missing path returns. On a catch-all / SPA host this is a
    200 + index, which would otherwise make EVERY sensitive path 'exist'."""
    rnd = f"/reconscan-cax-{secrets.token_hex(8)}"
    r = client.get(urljoin(base_url, rnd), phase="misconfig", allow_redirects=False)
    return {"status": r.status if r.ok else -1, "len": len(r.text or "")}


def check_sensitive_paths(client: Client, base_url: str) -> List[Finding]:
    findings: List[Finding] = []
    base = _catch_all_baseline(client, base_url)
    catch_all = base["status"] == 200      # host answers 200 for missing paths
    for path, (title, sev, advice) in SENSITIVE_PATHS.items():
        url = urljoin(base_url, path)
        resp = client.get(url, phase="misconfig", allow_redirects=False)
        if not resp.ok:
            continue
        # on a catch-all host, a 200 that's the same size as the not-found index is
        # the generic page, not the file — skip it at the source (no FP flood).
        if catch_all and resp.status == 200 and \
                abs(len(resp.text or "") - base["len"]) <= max(64, base["len"] * 0.05):
            continue
        if _status_indicates_present(resp.status):
            # extra validation for a couple of high-value files
            body_head = resp.text[:400]
            confidence = "firm"
            if path == "/.git/HEAD" and "ref:" not in body_head:
                confidence = "tentative"
            if path in ("/.env", "/.env.local", "/.env.bak"):
                if "=" not in resp.text[:2000] and resp.status == 200:
                    confidence = "tentative"
            sev_eff = sev
            if resp.status in (401, 403):
                # present but protected — downgrade, still worth noting
                sev_eff = "info" if sev in ("info", "low") else "low"
                confidence = "tentative"
            findings.append(Finding(
                title=title, severity=sev_eff, category="misconfig", target=url,
                evidence=f"HTTP {resp.status}, {len(resp.text)} bytes, "
                         f"content-type={resp.headers.get('content-type','')}.",
                recommendation=advice, confidence=confidence))
    return findings


def check_dir_listing(client: Client, base_url: str, candidate_dirs: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for d in candidate_dirs:
        url = urljoin(base_url, d if d.endswith("/") else d + "/")
        resp = client.get(url, phase="misconfig")
        if resp.ok and resp.status == 200:
            if any(re.search(p, resp.text, re.I) for p in DIR_LISTING_SIGNS):
                findings.append(Finding(
                    title="Directory listing enabled", severity="low",
                    category="misconfig", target=url,
                    evidence=f"Autoindex page returned at {url}.",
                    recommendation="Disable autoindex/Options -Indexes for this path.",
                    confidence="firm"))
    return findings


def check_verbose_errors(client: Client, base_url: str) -> List[Finding]:
    findings: List[Finding] = []
    # Benign, clearly-non-malicious probe path designed to trigger a 404/500.
    probe_url = urljoin(base_url, "/reconscan-nonexistent-" + "x0x0x0")
    resp = client.get(probe_url, phase="misconfig")
    if not resp.ok:
        return findings
    body = resp.text
    for pattern, label in STACKTRACE_SIGNS:
        m = re.search(pattern, body)
        if m:
            snippet = body[max(0, m.start() - 40): m.start() + 120]
            snippet = re.sub(r"\s+", " ", snippet).strip()
            findings.append(Finding(
                title=f"Verbose error / stack trace exposed ({label})",
                severity="medium", category="misconfig", target=probe_url,
                evidence=f"HTTP {resp.status}; matched '{label}': …{snippet}…",
                recommendation="Disable debug mode; return generic error pages.",
                confidence="firm"))
            break  # one signal is enough
    return findings


def check(client: Client, probe: dict, endpoint_data: dict) -> List[Finding]:
    base_url = probe.get("final_url") or probe.get("url")
    log("step", f"Misconfiguration checks on {base_url}")
    findings: List[Finding] = []
    findings += check_sensitive_paths(client, base_url)

    # candidate dirs to test for listing: a few common ones + the directory-looking
    # paths we actually discovered (the discovered set was previously built but
    # dropped — folding it in catches app-specific listable dirs like /ftp).
    discovered = [d["url"] for d in endpoint_data.get("discovered", [])
                  if isinstance(d, dict) and d.get("url")]
    common = ["/uploads", "/files", "/images", "/assets", "/backup", "/static",
              "/ftp", "/public", "/media", "/downloads", "/data", "/logs", "/tmp"]
    disc_dirs = []
    for u in discovered:
        p = urlparse(u).path
        seg = p.rsplit("/", 1)[-1]
        if "?" in u or "." in seg or not p or p == "/":
            continue                      # skip files / query URLs / root
        disc_dirs.append(p)
    cand = dedup_keep_order(common + disc_dirs)[:30]
    findings += check_dir_listing(client, base_url, cand)
    findings += check_verbose_errors(client, base_url)

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {f.target}")
    return findings

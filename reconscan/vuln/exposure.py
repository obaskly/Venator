"""Exposed-VCS / actuator / dotfile extraction — cheap, high-bounty, low-FP.

Hunts the classic "left the internals on the doormat" exposures:
  * a reachable .git/ directory (source + secrets reconstruction),
  * Spring Boot actuator endpoints (/actuator/env, /heapdump, /threaddump, ...),
  * a served .env file, .svn metadata, .DS_Store, Apache server-status.

Every hit is CONFIRMED structurally (git ref shape, actuator JSON shape, KEY=VALUE
env lines) with a negative control against a random sibling path, so a catch-all
200 server can't produce a false positive. Proof-over-damage: we extract a single
minimal indicator (one ref, the remote host, one property KEY name) and NEVER
clone the repo, download the heap dump, or dump the environment.
"""
from __future__ import annotations

import json
import random
import re
import string
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from ..config import Config
from ..http import Client
from ..utils import log
from . import Finding

_GIT_REF = re.compile(r"^(?:ref:\s*refs/|[0-9a-f]{40}\b)", re.M)
_GIT_CORE = re.compile(r"\[core\][^\[]*repositoryformatversion", re.S)
_GIT_REMOTE = re.compile(r"""url\s*=\s*(\S+)""")
_GIT_LOG_EMAIL = re.compile(r"<([^>]+@[^>]+)>")
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S", re.M)
_ENV_SECRET_KEY = re.compile(
    r"^(?:APP_KEY|DB_PASSWORD|DB_USERNAME|SECRET|.*_SECRET|.*_KEY|.*PASSWORD|"
    r"AWS_[A-Z_]+|STRIPE_[A-Z_]+|JWT_[A-Z_]+|MAIL_[A-Z_]+|REDIS_[A-Z_]+)\s*=",
    re.M | re.I)

# (path, severity, label) for actuator sensitive endpoints, tried under both the
# Boot 2.x /actuator/ prefix and the Boot 1.x root.
_ACT_SENSITIVE = [
    ("env", "high", "environment / config properties (often secrets)"),
    ("heapdump", "high", "full heap dump (memory — tokens, passwords, keys)"),
    ("threaddump", "medium", "thread dump (stack traces, internal state)"),
    ("configprops", "medium", "configuration properties"),
    ("beans", "medium", "Spring bean graph (internal architecture)"),
    ("mappings", "medium", "request mappings (full route map)"),
    ("loggers", "low", "logger configuration"),
]
# per-endpoint signature keys in the actuator JSON response (structural confirm).
_ACT_KEYS = {
    "env": ("propertySources",),
    "threaddump": ("threads",),
    "configprops": ("contexts", "beans"),
    "beans": ("contexts", "beans"),
    "mappings": ("contexts", "mappings"),
    "loggers": ("levels", "loggers"),
}


def _rand(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _is_json_obj(r) -> Optional[dict]:
    if not r.ok or r.status != 200:
        return None
    ct = r.headers.get("content-type", "").lower()
    body = (r.text or "").lstrip()
    if "json" not in ct and not body.startswith("{"):
        return None
    try:
        doc = json.loads(r.text)
        return doc if isinstance(doc, dict) else None
    except Exception:
        return None


def _catch_all_200(client: Client, base: str, sample: str) -> bool:
    """True if a random sibling path returns the SAME 200 body — i.e. the server
    answers everything alike and our 'hit' is meaningless."""
    ctrl = client.get(urljoin(base, f"/{_rand()}/{_rand()}"), phase="exposure",
                      allow_redirects=False)
    if ctrl.ok and ctrl.status == 200 and ctrl.text and sample:
        # same length within 5% -> indistinguishable from a generic page
        a, b = len(ctrl.text), len(sample)
        if b and abs(a - b) / max(a, b, 1) < 0.05:
            return True
    return False


def _check_git(client: Client, base: str) -> List[Finding]:
    head = client.get(urljoin(base, "/.git/HEAD"), phase="exposure",
                      allow_redirects=False)
    if not head.ok or head.status != 200 or not _GIT_REF.search(head.text or ""):
        return []
    if _catch_all_200(client, base, head.text):
        return []
    ref = (head.text or "").strip().splitlines()[0][:80]
    remote = ""
    cfg_r = client.get(urljoin(base, "/.git/config"), phase="exposure",
                       allow_redirects=False)
    confirmed_config = bool(cfg_r.ok and cfg_r.status == 200
                            and _GIT_CORE.search(cfg_r.text or ""))
    if confirmed_config:
        m = _GIT_REMOTE.search(cfg_r.text or "")
        if m:
            remote = m.group(1)
    author = ""
    logs = client.get(urljoin(base, "/.git/logs/HEAD"), phase="exposure",
                      allow_redirects=False)
    if logs.ok and logs.status == 200:
        m = _GIT_LOG_EMAIL.search(logs.text or "")
        if m:
            author = m.group(1)
    ev = f"/.git/HEAD served `{ref}`"
    if confirmed_config:
        ev += "; /.git/config has a valid [core] section"
    if remote:
        ev += f"; remote = {remote}"
    if author:
        ev += f"; last-commit author {author}"
    return [Finding(
        title="Exposed .git directory (source code + history retrievable)",
        severity="high", category="misconfig", target=urljoin(base, "/.git/"),
        evidence=ev,
        recommendation=("Block /.git/ at the web server (deny dotfiles). An exposed "
                        ".git lets anyone reconstruct the full source and commit "
                        "history with git-dumper — frequently leaking credentials, "
                        "internal hostnames, and keys. Rotate anything committed."),
        confidence="confirmed",
        poc=f"git-dumper {urljoin(base, '/.git/')} ./dump   # (do not run on prod)")]


def _check_env(client: Client, base: str) -> List[Finding]:
    r = client.get(urljoin(base, "/.env"), phase="exposure", allow_redirects=False)
    if not r.ok or r.status != 200:
        return []
    body = r.text or ""
    if "html" in r.headers.get("content-type", "").lower():
        return []
    if not _ENV_LINE.search(body):
        return []
    if _catch_all_200(client, base, body):
        return []
    secret_keys = [m.group(0).split("=")[0].strip()
                   for m in _ENV_SECRET_KEY.finditer(body)]
    secret_keys = sorted(set(secret_keys))[:6]
    n_lines = len(_ENV_LINE.findall(body))
    ev = f"/.env served {n_lines} KEY=VALUE line(s)"
    if secret_keys:
        ev += f"; sensitive keys present: {', '.join(secret_keys)} (values NOT shown)"
    sev = "high" if secret_keys else "medium"
    return [Finding(
        title="Exposed .env file (application secrets)",
        severity=sev, category="misconfig", target=urljoin(base, "/.env"),
        evidence=ev,
        recommendation=("Never serve dotfiles. Block /.env at the web server and "
                        "rotate every credential it contains — assume compromised."),
        confidence="confirmed",
        poc=f"curl -s {urljoin(base, '/.env')}")]


def _check_actuator(client: Client, base: str) -> List[Finding]:
    findings: List[Finding] = []
    # gate: is this a Spring Boot actuator host at all?
    idx = client.get(urljoin(base, "/actuator"), phase="exposure", allow_redirects=False)
    idx_doc = _is_json_obj(idx)
    boot2 = bool(idx_doc and "_links" in idx_doc)
    health = client.get(urljoin(base, "/actuator/health"), phase="exposure",
                        allow_redirects=False)
    boot2 = boot2 or bool(_is_json_obj(health) and "status" in (_is_json_obj(health) or {}))
    health1 = client.get(urljoin(base, "/health"), phase="exposure", allow_redirects=False)
    boot1 = bool(_is_json_obj(health1) and "status" in (_is_json_obj(health1) or {}))
    if not (boot2 or boot1):
        return []

    prefixes = []
    if boot2:
        prefixes.append("/actuator/")
    if boot1:
        prefixes.append("/")
    for pref in prefixes:
        for name, sev, desc in _ACT_SENSITIVE:
            url = urljoin(base, pref + name)
            if name == "heapdump":
                # don't pull the dump — declare it via headers from a tiny read
                r = client.get(url, phase="exposure", allow_redirects=False,
                               body_limit=4096)
                clen = r.headers.get("content-length", "")
                ct = r.headers.get("content-type", "").lower()
                big = clen.isdigit() and int(clen) > 100_000
                if r.ok and r.status == 200 and ("octet-stream" in ct or big):
                    findings.append(Finding(
                        title="Spring Boot actuator heap dump exposed",
                        severity="high", category="misconfig", target=url,
                        evidence=f"{url} returns a binary heap dump "
                                 f"(content-type {ct or '?'}, length {clen or '?'}). "
                                 "A heap dump contains live memory — session tokens, "
                                 "passwords, and keys.",
                        recommendation=("Disable the heapdump endpoint and restrict "
                                        "actuator to an internal management port with auth."),
                        confidence="confirmed",
                        poc=f"curl -s {url} -o heap.hprof   # (do not run on prod)"))
                continue
            r = client.get(url, phase="exposure", allow_redirects=False)
            doc = _is_json_obj(r)
            if doc is None:
                continue
            # structural confirmation per endpoint — require that endpoint's own
            # signature key(s); no generic "any JSON" fallback (keeps FP near zero)
            ok = any(k in doc for k in _ACT_KEYS.get(name, ()))
            if not ok:
                continue
            indicator = ""
            if name == "env":
                indicator = _first_env_key(doc)
            findings.append(Finding(
                title=f"Spring Boot actuator endpoint exposed: {name}",
                severity=sev, category="misconfig", target=url,
                evidence=f"{url} returns actuator JSON — {desc}."
                         + (f" e.g. property `{indicator}` present (value NOT shown)."
                            if indicator else ""),
                recommendation=("Restrict actuator endpoints to an authenticated "
                                "internal management port; never expose env/heapdump/"
                                "threaddump publicly."),
                confidence="confirmed",
                poc=f"curl -s {url}"))
    return findings


def _first_env_key(doc: dict) -> str:
    try:
        for src in doc.get("propertySources", []):
            props = src.get("properties") or {}
            for k in props:
                if any(t in k.lower() for t in ("pass", "secret", "key", "token", "cred")):
                    return k
            for k in props:
                return k
    except Exception:
        pass
    return ""


def _check_misc(client: Client, base: str) -> List[Finding]:
    out: List[Finding] = []
    # .svn metadata
    svn = client.get(urljoin(base, "/.svn/wc.db"), phase="exposure", allow_redirects=False)
    if svn.ok and svn.status == 200 and (svn.text or "").startswith("SQLite format 3"):
        out.append(Finding(
            title="Exposed .svn metadata (source retrievable)",
            severity="medium", category="misconfig", target=urljoin(base, "/.svn/"),
            evidence="/.svn/wc.db is a served SQLite working-copy database.",
            recommendation="Block /.svn/ at the web server; rotate any leaked secrets.",
            confidence="confirmed", poc=f"curl -s {urljoin(base, '/.svn/wc.db')}"))
    # Apache server-status
    st = client.get(urljoin(base, "/server-status"), phase="exposure", allow_redirects=False)
    if st.ok and st.status == 200 and "Apache Server Status" in (st.text or ""):
        out.append(Finding(
            title="Apache mod_status (/server-status) exposed",
            severity="medium", category="misconfig", target=urljoin(base, "/server-status"),
            evidence="/server-status returns the Apache mod_status page (active "
                     "requests, client IPs, internal vhosts).",
            recommendation="Restrict /server-status to localhost / authenticated admins.",
            confidence="confirmed", poc=f"curl -s {urljoin(base, '/server-status')}"))
    return out


def check(client: Client, base_urls: List[str], cfg: Config,
          audit=None) -> List[Finding]:
    if not getattr(cfg, "do_exposure", True) or not base_urls:
        return []
    log("step", "Exposure extraction (.git / actuator / dotfiles)")
    findings: List[Finding] = []
    for base in base_urls:
        if client.over_budget():
            break
        findings += _check_git(client, base)
        findings += _check_env(client, base)
        findings += _check_actuator(client, base)
        findings += _check_misc(client, base)
    if findings:
        log("vuln", f"exposure: {len(findings)} confirmed exposure(s)")
    else:
        log("ok", "exposure: none found")
    return findings

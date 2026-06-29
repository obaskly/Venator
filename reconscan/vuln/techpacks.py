"""Technology-specific exploit packs — once the stack is fingerprinted, run the
targeted, high-payout checks that generic scanning misses, and cross-reference the
detected version against the CVEs attackers actually use (CISA-KEV flagged).

Confirmed-where-safe (zero-FP, structural oracle, read-only):
  * WordPress  — REST user enumeration (/wp-json/wp/v2/users) + XML-RPC pingback/
                 multicall amplification (/xmlrpc.php).
  * Jenkins    — unauthenticated Groovy /script console (= direct RCE) + /api/json.
  * Jira       — unauth /rest/api/2/serverInfo version disclosure.
  * Confluence — version disclosure.
  * GitLab     — /api/v4/version disclosure.

Plus version→CVE heuristics (data.TECH_CVES): a detected product below a known-
vulnerable build is flagged (tentative — confirm exact build) and, when the CVE is
on KEV, the scorer floats it to the top of the hunt list. These findings carry the
CVE id so the CVE-intel phase auto-enriches them with PoC/advisory links.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from ..config import Config
from ..data import KEV_CVES, TECH_CVES
from ..http import Client
from ..utils import log
from ..vuln import Finding

_WP_GEN = re.compile(r'name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)', re.I)
_CONF_VER = re.compile(r'Confluence(?:\s+|[^\d]{0,20})([6-9]\.\d[\d.]*)', re.I)
_GL_VER = re.compile(r'GitLab[^<]{0,40}?([\d]+\.\d+\.\d+)', re.I)


def _vt(s: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", s)) if s else ()


def _version_cves(product: str, version: str, target: str) -> List[Finding]:
    out: List[Finding] = []
    vt = _vt(version)
    if not vt:
        return out
    for prod, maxv, cve, sev, note in TECH_CVES:
        if prod != product:
            continue
        mv = _vt(maxv)
        if mv and vt < mv:
            kev = cve in KEV_CVES
            out.append(Finding(
                title=f"{product.title()} {version} likely vulnerable to {cve}"
                      + (" [KEV]" if kev else ""),
                severity=sev, category="cve", target=target,
                evidence=(f"detected {product} {version} (< {maxv}): {note}."
                          + (" On CISA's Known-Exploited-Vulnerabilities list — actively "
                             "exploited in the wild." if kev else "")
                          + " Confirm the exact build, then validate exploitability."),
                recommendation=f"Upgrade {product} past {maxv}; verify {cve} applicability "
                               "against your build.",
                confidence="tentative"))
    return out


def _wordpress(client: Client, base: str, body: str) -> List[Finding]:
    out: List[Finding] = []
    # REST user enumeration (confirmed structurally)
    ru = client.get(base + "/wp-json/wp/v2/users", phase="vuln")
    if ru.ok and ru.status == 200:
        try:
            users = json.loads(ru.text or "")
        except Exception:
            users = None
        if isinstance(users, list) and users and isinstance(users[0], dict) \
                and any("slug" in u for u in users):
            names = [u.get("slug") or u.get("name") for u in users][:8]
            out.append(Finding(
                title="WordPress REST API user enumeration",
                severity="medium", category="exploit", target=base + "/wp-json/wp/v2/users",
                evidence=(f"the WP REST users endpoint listed {len(users)} account(s) "
                          f"unauthenticated (logins: {names}). Provides valid usernames "
                          "for password spraying / brute force. EXPLOITED (user enum)."),
                recommendation=("Restrict /wp-json/wp/v2/users to authenticated requests "
                                "(disable REST user listing); enforce strong-password + "
                                "lockout policy."),
                confidence="confirmed",
                poc=f"curl -s '{base}/wp-json/wp/v2/users'"))
            log("vuln", f"[medium] WP REST user-enum @ {base} ({len(users)} users)")
    # XML-RPC pingback / multicall amplification
    xml = ("<?xml version=\"1.0\"?><methodCall>"
           "<methodName>system.listMethods</methodName><params></params></methodCall>")
    rx = client.post_raw(base + "/xmlrpc.php", xml, "text/xml", phase="vuln")
    if rx.ok and "<methodresponse" in (rx.text or "").lower() \
            and "pingback.ping" in (rx.text or "").lower():
        multicall = "system.multicall" in (rx.text or "").lower()
        out.append(Finding(
            title="WordPress XML-RPC enabled (pingback SSRF + brute amplification)",
            severity="medium" if multicall else "low", category="exploit",
            target=base + "/xmlrpc.php",
            evidence=("xmlrpc.php answered system.listMethods and exposes pingback.ping"
                      + (" and system.multicall (hundreds of logins per request → "
                         "credential brute amplification)" if multicall else "")
                      + ". pingback.ping enables SSRF/port-scan via the target. EXPLOITED "
                      "(XML-RPC surface)."),
            recommendation=("Disable XML-RPC if unused, or block pingback.ping + "
                            "system.multicall; rate-limit and monitor xmlrpc.php."),
            confidence="confirmed",
            poc=f"curl -s '{base}/xmlrpc.php' -d "
                "'<methodCall><methodName>system.listMethods</methodName></methodCall>'"))
        log("vuln", f"[medium] WP XML-RPC enabled @ {base}")
    m = _WP_GEN.search(body or "")
    if m:
        out += _version_cves("wordpress", m.group(1), base)
    return out


def _jenkins(client: Client, base: str, hdrs: Dict) -> List[Finding]:
    out: List[Finding] = []
    # unauth Groovy script console = direct RCE
    rs = client.get(base + "/script", phase="vuln")
    low = (rs.text or "").lower()
    if rs.ok and rs.status == 200 and "/login" not in (rs.final_url or "") \
            and ("groovy" in low or "script console" in low):
        out.append(Finding(
            title="Jenkins Groovy script console exposed unauthenticated (RCE)",
            severity="critical", category="exploit", target=base + "/script",
            evidence=("/script returned the Groovy console without authentication — "
                      "anyone can run arbitrary Groovy/Java (full RCE on the controller). "
                      "EXPLOITED (unauth script console)."),
            recommendation=("Require authentication + enable CSRF protection; never expose "
                            "/script. Restrict the controller to trusted networks."),
            confidence="confirmed",
            poc=f"curl -s '{base}/script' --data-urlencode "
                "\"script=println 'id'.execute().text\""))
        log("vuln", f"[critical] Jenkins unauth script console @ {base}")
    ver = hdrs.get("x-jenkins", "")
    if ver:
        out += _version_cves("jenkins", ver, base)
    return out


def _jira(client: Client, base: str) -> List[Finding]:
    out: List[Finding] = []
    r = client.get(base + "/rest/api/2/serverInfo", phase="vuln")
    if r.ok and r.status == 200:
        try:
            info = json.loads(r.text or "")
        except Exception:
            info = {}
        ver = info.get("version", "")
        if ver:
            out.append(Finding(
                title=f"Jira version {ver} disclosed (unauthenticated serverInfo)",
                severity="low", category="exploit", target=base + "/rest/api/2/serverInfo",
                evidence=(f"/rest/api/2/serverInfo returned the build ({ver}) without auth — "
                          "pins the exact version for targeted CVE selection. EXPLOITED "
                          "(version disclosure)."),
                recommendation="Restrict serverInfo; keep Jira patched.",
                confidence="confirmed", poc=f"curl -s '{base}/rest/api/2/serverInfo'"))
            out += _version_cves("jira", ver, base)
    return out


def _confluence(client: Client, base: str, body: str) -> List[Finding]:
    m = _CONF_VER.search(body or "")
    if not m:
        r = client.get(base + "/", phase="vuln")
        m = _CONF_VER.search(r.text or "")
    return _version_cves("confluence", m.group(1), base) if m else []


def _gitlab(client: Client, base: str, body: str) -> List[Finding]:
    ver = ""
    r = client.get(base + "/api/v4/version", phase="vuln")
    if r.ok and r.status == 200:
        try:
            ver = json.loads(r.text or "").get("version", "")
        except Exception:
            ver = ""
    if not ver:
        m = _GL_VER.search(body or "")
        ver = m.group(1) if m else ""
    return _version_cves("gitlab", ver, base) if ver else []


def check(client: Client, service_bases: List[str], fingerprints: List[dict],
          cfg: Config) -> List[Finding]:
    if not service_bases:
        return []
    labels = {t.lower() for fp in (fingerprints or []) for t in fp.get("technologies", [])}
    findings: List[Finding] = []
    seen: set = set()
    for base in service_bases:
        host = urlparse(base).netloc
        if host in seen or client.over_budget():
            continue
        seen.add(host)
        r = client.get(base, phase="vuln")
        body = (r.text or "")[:200000]
        bl = body.lower()
        hdrs = r.headers or {}
        if "wordpress" in labels or "wp-content" in bl or "wp-includes" in bl or "/wp-json" in bl:
            findings += _wordpress(client, base, body)
        if "jenkins" in labels or "x-jenkins" in hdrs or ">jenkins<" in bl or "jenkins-session" in str(hdrs):
            findings += _jenkins(client, base, hdrs)
        if "jira" in bl or "x-arequestid" in hdrs or "atlassian" in bl:
            findings += _jira(client, base)
        if "confluence" in bl or "x-confluence-request-time" in hdrs:
            findings += _confluence(client, base, body)
        if "gitlab" in labels or "gitlab" in bl:
            findings += _gitlab(client, base, body)
    if findings:
        log("ok", f"tech-packs: {len(findings)} targeted finding(s)")
    return findings

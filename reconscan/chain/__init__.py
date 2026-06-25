"""Exploit-chaining engine.

Modern bounty payouts reward *chains*, not lone bugs: an open redirect is low
alone but critical if it steals an OAuth token; an IDOR plus a GUID leak is a
full breach. This engine inspects every finding plus a context snapshot
(login/OAuth/cookies/admin routes present) and assembles the chains whose
preconditions are met — each with the concrete attack path and an escalated
severity, so the report leads with submittable high-impact stories.

Refs: appsecure.security/blog/vulnerability-chaining-attacks ;
bugcrowd.com/blog/how-to-find-bugs-on-a-hardened-target-using-gadgets
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..utils import log
from ..vuln import Finding


def _by_cat(findings: List[Finding]) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for f in findings:
        out.setdefault(f.category, []).append(f)
    return out


def _has(findings: List[Finding], *, category=None, title_contains=None) -> Optional[Finding]:
    for f in findings:
        if category and f.category != category:
            continue
        if title_contains and title_contains.lower() not in f.title.lower():
            continue
        return f
    return None


def _chain(title, severity, parts: List[Finding], path: str, rec: str) -> Finding:
    tgt = parts[0].target if parts else ""
    ev = " + ".join(f"[{p.severity}] {p.title}" for p in parts)
    return Finding(
        title=f"CHAIN: {title}", severity=severity, category="chain", target=tgt,
        evidence=f"components: {ev}. Attack path: {path}",
        recommendation=rec, confidence="firm",
        priority=0)


# Each rule returns a chain Finding or None.
def _rule_sqli_ato(f, ctx):
    sqli = (_has(f, category="exploit", title_contains="auth bypass") or
            _has(f, category="exploit", title_contains="authentication bypass"))
    if sqli:
        return _chain(
            "Login auth bypass → authenticated account takeover", "critical", [sqli],
            "SQLi/NoSQLi login bypass → valid session/JWT → read/modify victim account "
            "data, escalate to admin",
            "Confirmed login bypass yields an authenticated session. Demonstrate access "
            "to another user's data for full ATO impact.")
    return None


def _rule_jwt_forge(f, ctx):
    j = (_has(f, category="exploit", title_contains="alg:none") or
         _has(f, category="exploit", title_contains="weak/guessable hmac"))
    if j:
        return _chain(
            "JWT forgery → admin impersonation", "critical", [j],
            "forge a JWT (alg:none or cracked secret) with an admin/role claim → "
            "authenticate as any user without credentials",
            "Mint a token with elevated claims and confirm an admin-only action.")
    return None


def _rule_massassign(f, ctx):
    m = _has(f, category="exploit", title_contains="mass assignment")
    if m:
        return _chain(
            "Mass assignment → self-provisioned admin → full compromise", "critical", [m],
            "register/update with an injected role=admin field → become admin → "
            "access every user's data and admin functionality",
            "Log in as the self-created admin account and confirm privileged access.")
    return None


def _rule_sqli_extract(f, ctx):
    sqli = _has(f, category="exploit", title_contains="sql injection (")
    if sqli:
        return _chain(
            "SQLi → database extraction → credential reuse", "critical", [sqli],
            "confirmed SQLi oracle → dump users/hashes → crack/reuse → broader access",
            "A confirmed SQLi oracle allows full DB extraction. Pull a single proof row "
            "(version/current_user) per program rules, then report.")
    return None


def _rule_xss_ato(f, ctx):
    x = _has(f, category="exploit", title_contains="xss") or \
        _has(f, category="xss")
    if x and ctx.get("has_cookies"):
        return _chain(
            "XSS → session cookie theft → account takeover", "critical", [x],
            "reflected XSS executes → exfiltrate session cookie / CSRF token → ride "
            "victim session → ATO (escalate to admin if stored)",
            "Build a cookie-stealing PoC against a test account; if the app lacks "
            "HttpOnly or the token is readable, this is full ATO.")
    if x:
        return _chain(
            "XSS → CSRF-token theft → privileged action", "high", [x],
            "XSS reads anti-CSRF token → forge state-changing request as victim",
            "Confirm a sensitive state-changing action is reachable via the stolen token.")
    return None


def _rule_openredirect_oauth(f, ctx):
    rd = _has(f, category="redirect")
    if rd and ctx.get("has_oauth"):
        return _chain(
            "Open redirect → OAuth authorization-code / token theft", "high", [rd],
            "attacker redirect_uri via open redirect → victim's OAuth code/token is sent "
            "to attacker → account takeover",
            "Validate the OAuth flow honors the redirect; capture a code with a test "
            "account to prove token theft. Classic high-payout chain.")
    if rd:
        return _chain(
            "Open redirect → phishing / SSO bounce", "medium", [rd],
            "trusted-domain redirect → credential phishing or SSO relay",
            "Pair with an SSO/login flow on this host to raise severity.")
    return None


def _rule_rce(f, ctx):
    r = (_has(f, category="exploit", title_contains="remote code execution") or
         _has(f, category="exploit", title_contains="command injection") or
         _has(f, category="exploit", title_contains="ssti →"))
    if r:
        return _chain(
            "RCE → full server compromise → lateral movement", "critical", [r],
            "code execution on the host → read secrets/env, pivot to internal network, "
            "dump the database, persist",
            "Confirmed code execution. Capture a minimal proof (id/hostname); do not "
            "run destructive commands. Top-tier impact.")
    return None


def _rule_xxe(f, ctx):
    x = _has(f, category="exploit", title_contains="xxe")
    if x:
        return _chain(
            "XXE → local file read → secret disclosure / SSRF", "critical", [x],
            "read app config / private keys via XXE, or pivot to SSRF with http:// "
            "entities to reach cloud metadata",
            "Read a secrets/config file as proof, then chain the leaked credentials.")
    return None


def _rule_smuggling(f, ctx):
    s = _has(f, category="smuggling")
    if s:
        return _chain(
            "Request smuggling → cache poisoning / auth bypass / cred capture", "critical", [s],
            "desync the front/back-end → poison the cache for all users, bypass front-end "
            "auth controls, or capture other users' requests",
            "Confirm with a controlled victim request in Burp (respect program rules).")
    return None


def _rule_ssrf_cloud(f, ctx):
    s = _has(f, category="exploit", title_contains="ssrf")
    if s:
        return _chain(
            "SSRF → cloud metadata → IAM credential theft", "critical", [s],
            "SSRF reaches 169.254.169.254 → read instance IAM credentials → "
            "authenticate to the cloud account → full infra compromise",
            "Pull the security-credentials path and confirm temporary keys (do not "
            "use them beyond proof) — top-tier payout.")
    return None


def _rule_lfi_source(f, ctx):
    lfi = _has(f, category="lfi") or _has(f, category="exploit", title_contains="traversal")
    if lfi:
        return _chain(
            "LFI → source/secret disclosure → escalation", "high", [lfi],
            "read app source / config (.env, db creds) via traversal → use leaked "
            "secrets to auth or pivot (RCE via log poisoning if writable)",
            "Read a config/source file as proof, harvest secrets, then demonstrate "
            "the access they unlock.")
    return None


def _rule_secret_api(f, ctx):
    sec = _has(f, category="secret")
    if sec:
        return _chain(
            "Leaked credential → direct API/service access", "high", [sec],
            "hardcoded key from JS bundle → authenticate to the API/3rd-party service → "
            "data access or further pivot",
            "Verify the key is live (without abusing it) and document the access scope.")
    return None


def _rule_nextjs_admin(f, ctx):
    mw = _has(f, title_contains="cve-2025-29927")
    if mw:
        return _chain(
            "Next.js middleware bypass → unauthenticated admin access", "critical", [mw],
            "x-middleware-subrequest skips auth middleware → reach gated admin/API routes "
            "without a session → full app compromise",
            "Enumerate the now-reachable protected routes; confirm sensitive "
            "functionality is exposed.")
    return None


def _rule_takeover_oauth(f, ctx):
    to = _has(f, category="takeover")
    if to and ctx.get("has_oauth"):
        return _chain(
            "Subdomain takeover → OAuth redirect hijack", "critical", [to],
            "claimed dangling subdomain hosts attacker content → if it's an allowed "
            "OAuth redirect_uri/cookie-scope, steal tokens/sessions",
            "Check whether the takeoverable host is a trusted redirect or cookie domain.")
    return None


def _rule_cache_storedxss(f, ctx):
    cp = _has(f, category="cache")
    x = _has(f, category="exploit", title_contains="xss") or _has(f, category="xss")
    if cp and x:
        return _chain(
            "Cache poisoning + XSS → stored XSS served to every user", "critical", [cp, x],
            "reflect XSS via an unkeyed header → poisoned response cached → all visitors "
            "get the payload (mass ATO)",
            "Highest-impact web chain: prove the poisoned entry is served to a second "
            "client (respecting program rules).")
    return None


def _rule_cors_xss(f, ctx):
    cors = _has(f, category="cors")
    x = _has(f, category="exploit", title_contains="xss") or _has(f, category="xss")
    if cors and x:
        return _chain(
            "CORS misconfiguration + XSS → cross-origin data exfiltration", "critical", [cors, x],
            "XSS payload makes a cross-origin request to the API (CORS allows it) → "
            "exfiltrate authenticated API response (PII, tokens, secrets) to attacker server",
            "Confirm by: (1) serving an XSS payload that calls the sensitive endpoint "
            "cross-origin and (2) observing the response in your OOB server. "
            "Fix: strict CORS + HttpOnly cookies + XSS encoding.")
    if cors:
        return _chain(
            "CORS misconfiguration → cross-origin data theft", "high", [cors],
            "arbitrary origin reflected with credentials → craft a page that calls the "
            "sensitive API on behalf of a logged-in victim and relays the response",
            "Demo by reading an authenticated endpoint from an attacker-controlled origin.")
    return None


def _rule_proto_rce(f, ctx):
    pp = _has(f, category="exploit", title_contains="prototype pollution")
    if pp:
        return _chain(
            "Prototype pollution → RCE / authentication bypass", "critical", [pp],
            "polluting Object.prototype can override security-critical properties "
            "(e.g. isAdmin, role) in downstream code, or reach a gadget chain that "
            "executes shell commands (e.g. child_process via a template engine or "
            "serialization gadget)",
            "Identify which prototype properties the application reads for access control "
            "or command execution, then demonstrate privilege escalation or code execution.")
    return None


def _rule_race_business(f, ctx):
    r = _has(f, category="exploit", title_contains="race condition")
    if r:
        return _chain(
            "Race condition → unlimited resource consumption / duplicate operation", "high", [r],
            "concurrent identical requests beat the guard → coupon/voucher applied "
            "multiple times, funds transferred twice, points/credits duplicated",
            "Confirm by measuring the actual financial/privilege impact per duplicate "
            "operation; calculate realistic dollar impact for the report.")
    return None


def _rule_log4shell_pivot(f, ctx):
    l4 = _has(f, category="exploit", title_contains="log4shell")
    if l4:
        return _chain(
            "Log4Shell → RCE → full server compromise", "critical", [l4],
            "JNDI callback confirmed → spin up a malicious LDAP server → "
            "execute arbitrary bytecode → read secrets/env, pivot to cloud metadata, "
            "dump DB, achieve persistent access",
            "CRITICAL — maximum severity. Upgrade Log4j immediately. "
            "Capture a minimal proof (hostname/id) for the report without causing damage.")
    return None


def _rule_hpp_bypass(f, ctx):
    hpp = _has(f, category="exploit", title_contains="parameter pollution")
    if hpp:
        return _chain(
            "HTTP Parameter Pollution → WAF bypass → injection", "high", [hpp],
            "duplicate parameters confuse WAF inspection (WAF checks first value, "
            "backend uses last) → sneak injection payloads past the filter",
            "Combine HPP with SQLi/XSS payloads: first param=clean, second param=payload. "
            "Demonstrate that the WAF passes but the backend evaluates the malicious value.")
    return None


_RULES: List[Callable] = [
    _rule_sqli_ato, _rule_jwt_forge, _rule_massassign, _rule_sqli_extract,
    _rule_rce, _rule_xxe, _rule_smuggling, _rule_xss_ato, _rule_ssrf_cloud,
    _rule_openredirect_oauth, _rule_lfi_source, _rule_secret_api,
    _rule_nextjs_admin, _rule_takeover_oauth, _rule_cache_storedxss,
    _rule_cors_xss, _rule_proto_rce, _rule_race_business,
    _rule_log4shell_pivot, _rule_hpp_bypass,
]


def build_chains(findings: List[Finding], context: dict) -> List[Finding]:
    chains: List[Finding] = []
    seen_titles = set()
    for rule in _RULES:
        try:
            c = rule(findings, context)
        except Exception:
            c = None
        if c and c.title not in seen_titles:
            seen_titles.add(c.title)
            chains.append(c)
            log("vuln", f"[{c.severity}] {c.title}")
    if chains:
        log("ok", f"chaining: {len(chains)} attack chain(s) assembled")
    return chains

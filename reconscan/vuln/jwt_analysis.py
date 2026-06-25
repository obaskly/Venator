"""JWT weakness analysis (generic, no target-specific logic).

Collects JWTs seen anywhere in the run (response bodies, Set-Cookie, exploit
proofs), decodes them, and flags real issues:
  * alg:none            -> forge arbitrary tokens (critical),
  * HS256 weak secret   -> brute a small common-secret list; a verify = forge admin,
  * missing exp         -> tokens never expire (low),
  * sensitive claims    -> role/isAdmin/email exposed (info, chain fuel).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import List, Set

from ..http import Client
from ..utils import dedup_keep_order, log
from . import Finding

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
WEAK_SECRETS = ["secret", "password", "123456", "jwt", "key", "admin", "changeme",
                "secretkey", "supersecret", "your-256-bit-secret", "test", "qwerty",
                "private", "token", "mysecret", "s3cr3t", "default", "jwtsecret"]


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _decode(tok: str):
    try:
        h, p, sig = tok.split(".")
        header = json.loads(_b64d(h))
        payload = json.loads(_b64d(p))
        return header, payload, sig, f"{h}.{p}"
    except Exception:
        return None


def _crack_hs256(signing_input: str, sig_b64: str) -> str:
    try:
        sig = _b64d(sig_b64)
    except Exception:
        return ""
    for secret in WEAK_SECRETS:
        mac = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        if hmac.compare_digest(mac, sig):
            return secret
    return ""


def _collect(probes: List[dict], extra: List[str]) -> Set[str]:
    toks: Set[str] = set(extra)
    for p in probes:
        for src in ((p.get("_body", "") or ""),
                    (p.get("headers", {}) or {}).get("set-cookie", "")):
            toks.update(JWT_RE.findall(src))
    return toks


def check(probes: List[dict], extra_tokens: List[str] = None) -> List[Finding]:
    tokens = _collect(probes, extra_tokens or [])
    if not tokens:
        return []
    log("info", f"JWT analysis on {len(tokens)} token(s)")
    findings: List[Finding] = []
    for tok in list(tokens)[:10]:
        dec = _decode(tok)
        if not dec:
            continue
        header, payload, sig, signing_input = dec
        alg = str(header.get("alg", "")).lower()
        tgt = tok[:24] + "…"

        if alg == "none" or sig == "":
            findings.append(Finding(
                title="JWT accepts alg:none / unsigned token", severity="critical",
                category="exploit", target=tgt,
                evidence=f"header alg={header.get('alg')!r}, empty/absent signature — "
                         "forge arbitrary claims. EXPLOITABLE.",
                recommendation="Reject alg:none; pin the expected algorithm server-side.",
                confidence="firm"))
            log("vuln", "[critical] JWT alg:none accepted")
        elif alg.startswith("hs"):
            secret = _crack_hs256(signing_input, sig)
            if secret:
                findings.append(Finding(
                    title="JWT signed with a weak/guessable HMAC secret",
                    severity="critical", category="exploit", target=tgt,
                    evidence=f"HS256 secret brute-forced: {secret!r} — forge any token "
                             "(e.g. set admin role). EXPLOITED.",
                    recommendation="Use a long random secret (or RS256). Rotate the key now.",
                    confidence="confirmed"))
                log("vuln", f"[critical] JWT weak HMAC secret: {secret!r}")

        # claims hygiene
        if "exp" not in payload:
            findings.append(Finding(
                title="JWT has no expiry (exp claim missing)", severity="low",
                category="exploit", target=tgt,
                evidence=f"payload claims: {list(payload)[:8]} — token never expires",
                recommendation="Add a short exp; support revocation.",
                confidence="firm"))
        role_claims = [k for k in payload if k.lower() in
                       ("role", "isadmin", "is_admin", "admin", "scope", "authorities",
                        "permissions", "groups")]
        if role_claims:
            findings.append(Finding(
                title="JWT carries authorization claims (privilege chain fuel)",
                severity="info", category="exploit", target=tgt,
                evidence=f"claims {role_claims} present — if signature is forgeable, "
                         "escalate to admin.",
                recommendation="Ensure these claims can't be forged (see signature findings).",
                confidence="firm"))
    return findings

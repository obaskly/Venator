"""Bounty-hunt prioritization.

Severity alone doesn't tell a hunter what to look at first. This scores each
finding by *expected payoff*: severity + exploitability (public PoC? confirmed?)
+ asset value (auth/payment/admin/API surface) + confidence. The report then
leads with a ranked 'hunt these first' list instead of a flat dump.
"""
from __future__ import annotations

from typing import List, Optional, Set
from urllib.parse import urlparse

from .vuln import Finding

# finding categories that gain priority when they sit on a gf-classified
# high-value parameter (see recon/urlclass.py)
_HOT_PARAM_CATS = {"sqli", "ssrf", "lfi", "ssti", "redirect", "xss", "exploit",
                   "cmdi", "rce", "idor", "bypass"}

_SEV_BASE = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}

_CATEGORY_BONUS = {
    "chain": 80,          # assembled high-impact attack path = top of the report
    "exploit": 60,        # CONFIRMED + PoC (not just a lead)
    "secret": 40,         # hardcoded creds = fast, high-value submissions
    "sqli": 40,           # confirmed-class injection leads = top priority
    "ssti": 40,
    "takeover": 35,       # subdomain takeover = clean, well-paid
    "lfi": 35,
    "bypass": 32,         # access-control bypass = strong, well-paid
    "xss": 25,
    "smuggling": 36,      # request smuggling = high-impact, well-paid
    "cache": 22,          # cache poisoning / host-header injection
    "redirect": 18,       # open redirect (chain fuel)
    "exploit-intel": 20,  # known CVE with public PoC
    "csrf": 10,
    "cors": 10,
    "misconfig": 8,
    "email": 4,           # SPF/DMARC — real but low payout
}

# High-value asset signals in the target URL/host.
_HOT_WORDS = ("admin", "api", "graphql", "oauth", "sso", "auth", "login",
              "token", "account", "payment", "pay", "billing", "invoice",
              "upload", "internal", "debug", "actuator", "config", ".git",
              ".env", "user", "password", "secret", "key")


def _exploitability(f: Finding) -> int:
    score = 0
    ev = f.evidence.lower()
    if f.category == "exploit-intel" and "exploitdb poc" in ev:
        score += 30
    if f.confidence == "firm":
        score += 10
    if f.confidence == "confirmed" or f.validated is True:
        score += 18
    return score


def _asset_value(f: Finding) -> int:
    blob = (f.target + " " + f.title).lower()
    return min(25, 6 * sum(1 for w in _HOT_WORDS if w in blob))


def _on_hot_target(target: str, hot_targets: Set[str]) -> bool:
    if not hot_targets:
        return False
    try:
        pr = urlparse(target)
    except Exception:
        return False
    return f"{pr.netloc}{pr.path}" in hot_targets


def score_finding(f: Finding, hot_targets: Optional[Set[str]] = None) -> int:
    s = _SEV_BASE.get(f.severity, 5)
    s += _CATEGORY_BONUS.get(f.category, 0)
    s += _exploitability(f)
    s += _asset_value(f)
    if f.validated is True:
        s += 8
    # gf-classified high-value parameter on this URL -> bump it up the hunt list
    if f.category in _HOT_PARAM_CATS and _on_hot_target(f.target, hot_targets):
        s += 10
    return s


def prioritize(findings: List[Finding],
               hot_targets: Optional[Set[str]] = None) -> List[Finding]:
    for f in findings:
        f.priority = score_finding(f, hot_targets)
    return findings


def top_hunts(findings: List[Finding], n: int = 8) -> List[Finding]:
    ranked = sorted(findings, key=lambda f: -f.priority)
    # exclude pure-informational noise from the headline list
    meaningful = [f for f in ranked if f.severity != "info" or f.priority >= 40]
    return (meaningful or ranked)[:n]

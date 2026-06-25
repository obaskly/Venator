"""Subdomain enumeration.

Sources (all API-key-free):
  * crt.sh certificate transparency JSON (with retries; flaky upstream)
  * subfinder passive aggregation (if installed)
  * DNS brute force with a small built-in wordlist (rate-limited via threads cap)

All discovered names are filtered to the apex scope, then resolved to keep
only live (resolvable) hosts.
"""
from __future__ import annotations

import concurrent.futures as cf
import secrets
import time
from typing import Dict, List, Set

import requests

from ..audit import AuditLog
from ..config import Config
from ..data import SUBDOMAIN_WORDS
from ..external import have, run, parse_jsonl
from ..utils import Scope, dedup_keep_order, log, valid_hostname
from . import dns_records


def _crtsh(apex: str, audit: AuditLog, retries: int = 3) -> Set[str]:
    found: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    for attempt in range(1, retries + 1):
        audit.record("GET", url, phase="subdomains", tool="crt.sh",
                     note=f"attempt {attempt}")
        try:
            r = requests.get(url, timeout=30,
                             headers={"User-Agent": "reconscan/0.1"})
            if r.status_code == 200 and r.text.strip():
                for row in r.json():
                    for nm in str(row.get("name_value", "")).splitlines():
                        nm = nm.strip().lstrip("*.").lower()
                        if nm.endswith(apex) and valid_hostname(nm):
                            found.add(nm)
                log("ok", f"crt.sh: {len(found)} names")
                return found
            log("warn", f"crt.sh HTTP {r.status_code} (attempt {attempt})")
        except Exception as e:
            log("warn", f"crt.sh error: {type(e).__name__} (attempt {attempt})")
        time.sleep(2 * attempt)
    log("warn", "crt.sh unavailable — relying on other sources")
    return found


def _subfinder(apex: str, audit: AuditLog) -> Set[str]:
    if not have("subfinder"):
        return set()
    log("info", "running subfinder (passive)")
    cp = run(["subfinder", "-d", apex, "-silent", "-all", "-json"],
             timeout=300, audit=audit, phase="subdomains")
    found: Set[str] = set()
    for obj in parse_jsonl(cp.stdout):
        h = str(obj.get("host", "")).lower().strip()
        if h.endswith(apex) and valid_hostname(h):
            found.add(h)
    # subfinder sometimes emits plain lines too
    if not found:
        for line in cp.stdout.splitlines():
            h = line.strip().lower()
            if h.endswith(apex) and valid_hostname(h):
                found.add(h)
    log("ok", f"subfinder: {len(found)} names")
    return found


def _detect_wildcard(apex: str, samples: int = 4) -> Set[str]:
    """Resolve several random, certainly-nonexistent labels. If they resolve, a
    wildcard DNS record is in play — record every address it answers with so we
    can drop brute-forced 'subdomains' that are just the wildcard. The #1 source
    of subdomain false positives at scale."""
    wildcard_ips: Set[str] = set()
    hits = 0
    for _ in range(samples):
        rnd = f"reconscan-wc-{secrets.token_hex(6)}.{apex}"
        addrs = dns_records.resolve_a(rnd)
        if addrs:
            hits += 1
            wildcard_ips.update(addrs)
    if hits >= max(2, samples // 2):
        log("warn", f"wildcard DNS detected on *.{apex} "
                    f"({len(wildcard_ips)} addr) — brute hits matching it are dropped")
        return wildcard_ips
    return set()


def _brute(apex: str, words: List[str], threads: int) -> Dict[str, List[str]]:
    log("info", f"DNS brute force ({len(words)} words)")
    candidates = [f"{w}.{apex}" for w in words]
    live: Dict[str, List[str]] = {}

    def check(host: str):
        addrs = dns_records.resolve_a(host)
        return (host, addrs) if addrs else None

    with cf.ThreadPoolExecutor(max_workers=max(2, threads)) as ex:
        for res in ex.map(check, candidates):
            if res:
                live[res[0]] = res[1]
                log("ok", f"brute hit: {res[0]}", detail=True)
    return live


def _load_words(cfg: Config) -> List[str]:
    if cfg.dns_wordlist:
        try:
            with open(cfg.dns_wordlist, encoding="utf-8") as fh:
                return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            log("warn", f"dns wordlist unreadable ({e}); using built-in")
    return SUBDOMAIN_WORDS


def enumerate_subdomains(cfg: Config, scope: Scope, audit: AuditLog) -> List[dict]:
    apex = cfg.target
    log("step", f"Subdomain enumeration for {apex}")

    # passive sources are trustworthy (real certs / OSINT) — never wildcard-filtered
    passive: Set[str] = {apex}
    passive |= _crtsh(apex, audit)
    if cfg.use_external:
        passive |= _subfinder(apex, audit)

    # active brute is wildcard-prone → detect + filter
    wildcard_ips = _detect_wildcard(apex)
    brute = _brute(apex, _load_words(cfg), cfg.threads)
    dropped = 0
    brute_names: Set[str] = set()
    for name, addrs in brute.items():
        if wildcard_ips and addrs and set(addrs).issubset(wildcard_ips):
            dropped += 1
            continue
        brute_names.add(name)
    if dropped:
        log("ok", f"wildcard filter: dropped {dropped} false brute hit(s)")

    names = {n for n in (passive | brute_names) if scope.host_in_scope(n)}
    names_list = sorted(names)[: cfg.max_subdomain_resolve]
    log("info", f"resolving {len(names_list)} unique candidate names")

    results: List[dict] = []

    def resolve(host: str):
        addrs = dns_records.resolve_a(host)
        return {"host": host, "addresses": addrs, "live": bool(addrs)}

    with cf.ThreadPoolExecutor(max_workers=max(2, cfg.threads)) as ex:
        for res in ex.map(resolve, names_list):
            results.append(res)

    live = [r for r in results if r["live"]]
    log("ok", f"{len(live)} live / {len(results)} total subdomains")
    return sorted(results, key=lambda r: (not r["live"], r["host"]))

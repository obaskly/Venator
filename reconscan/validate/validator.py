"""Re-confirm findings, kill soft-404 false positives, dedupe."""
from __future__ import annotations

import secrets
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from ..config import Config
from ..data import SECURITY_HEADERS
from ..http import Client
from ..utils import log
from ..vuln import Finding


def _baseline_404(client: Client, base: str, cache: Dict[str, dict]) -> dict:
    """Fetch a guaranteed-missing path so we know what this host's 'not found'
    looks like (status + body length). Used to spot soft-404s."""
    p = urlparse(base)
    root = f"{p.scheme}://{p.netloc}"
    if root in cache:
        return cache[root]
    rnd = f"/{secrets.token_hex(16)}/does-not-exist-{secrets.token_hex(4)}"
    resp = client.get(root + rnd, phase="validate")
    info = {"status": resp.status, "len": len(resp.text or "")}
    cache[root] = info
    return info


def _looks_soft_404(resp_status: int, resp_len: int, base404: dict) -> bool:
    if base404["status"] in (200, 0):
        # host returns 200 for missing paths → any 200 is suspect; compare size
        if resp_status == 200 and abs(resp_len - base404["len"]) <= max(64, base404["len"] * 0.05):
            return True
    return False


def _validate_header_finding(client: Client, f: Finding) -> None:
    # finding.target is the URL; the missing header name is embedded in the title
    header = None
    for h in SECURITY_HEADERS:
        if h in f.title.lower():
            header = h
            break
    if not header:
        f.validated = None
        return
    resp = client.get(f.target, phase="validate")
    if not resp.ok:
        f.validated = None
        f.fp_note = "could not re-fetch to confirm"
        return
    if header in resp.headers:
        f.validated = False
        f.fp_note = f"header '{header}' present on re-check — false positive"
    else:
        f.validated = True
        f.fp_note = "re-confirmed missing on second request"


def _validate_path_finding(client: Client, f: Finding, cache: Dict[str, dict]) -> None:
    if not f.target.startswith(("http://", "https://")):
        f.validated = None
        return
    resp = client.get(f.target, phase="validate")
    if not resp.ok or resp.status >= 400:
        f.validated = False
        f.fp_note = f"re-fetch returned {resp.status or 'error'} — not actually exposed"
        return
    base404 = _baseline_404(client, f.target, cache)
    if _looks_soft_404(resp.status, len(resp.text or ""), base404):
        f.validated = False
        f.fp_note = ("response indistinguishable from this host's soft-404 "
                     f"baseline (len~{base404['len']}) — likely false positive")
        return
    f.validated = True
    f.fp_note = "re-confirmed reachable, distinct from soft-404 baseline"


def validate(client: Client, findings: List[Finding], cfg: Config
             ) -> Tuple[List[Finding], List[Finding], dict]:
    """Returns (kept, filtered, summary). filtered = likely false positives."""
    log("step", f"Validation / false-positive filtering ({len(findings)} findings)")

    # 1) dedupe by (title, target)
    seen = set()
    deduped: List[Finding] = []
    dups = 0
    for f in findings:
        key = (f.title, f.target)
        if key in seen:
            dups += 1
            continue
        seen.add(key)
        deduped.append(f)

    cache: Dict[str, dict] = {}
    for f in deduped:
        if f.category == "headers":
            _validate_header_finding(client, f)
        elif f.category == "misconfig":
            _validate_path_finding(client, f, cache)
        elif f.category == "nuclei":
            # nuclei is high-quality but its simpler "does this path return 200?"
            # matchers false-positive en masse on catch-all / soft-404 hosts (an
            # SPA serves 200 + index.html for EVERY path, so /.git/HEAD, /.env,
            # /phpinfo.php all "exist"). Soft-404-validate any nuclei finding that
            # points at a specific path: a genuine endpoint (/metrics, swagger)
            # returns content distinct from the host's not-found baseline and is
            # kept; an exposure that's really just the catch-all index is filtered.
            pr = urlparse(f.target)
            if f.target.startswith(("http://", "https://")) and pr.path not in ("", "/"):
                _validate_path_finding(client, f, cache)
            else:
                f.validated = None  # root-level tech/detect finding — trust nuclei
        elif f.category in ("cors", "tls", "exploit-intel", "takeover"):
            f.validated = None  # external/structural — trust the source tool
        elif f.category in ("secret", "reflection", "cve", "sqli", "ssti",
                            "lfi", "xss", "bypass", "redirect", "cache", "csrf",
                            "smuggling"):
            f.validated = None
            f.fp_note = f.fp_note or "active lead — requires manual confirmation (not auto-exploited)"
        elif f.category == "email":
            f.validated = True  # DNS-derived, deterministic
        elif f.category == "exploit":
            f.validated = True  # confirmed by execution (PoC captured)
            f.fp_note = f.fp_note or "EXPLOITED — confirmed with proof-of-concept"
        elif f.category == "chain":
            f.validated = None
            f.fp_note = f.fp_note or "assembled chain — validate end-to-end before submit"

    kept = [f for f in deduped if f.validated is not False]
    filtered = [f for f in deduped if f.validated is False]

    confirmed = sum(1 for f in kept if f.validated is True)
    log("ok", f"validation: {len(kept)} kept ({confirmed} re-confirmed), "
              f"{len(filtered)} filtered as likely FP, {dups} duplicates removed")
    summary = {
        "input": len(findings),
        "duplicates_removed": dups,
        "reconfirmed": confirmed,
        "filtered_false_positive": len(filtered),
        "kept": len(kept),
        "filtered_titles": [f"{f.title} @ {f.target} ({f.fp_note})" for f in filtered],
    }
    return kept, filtered, summary

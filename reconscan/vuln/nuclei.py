"""nuclei integration for template-based detection — FULL template set.

Runs when the `nuclei` binary is present and --nuclei is enabled. Runs the entire
template library (every tag + severity) with the interactsh OOB collaborator on so
blind bugs (SSRF/RCE/SSTI/log4shell) self-confirm via callback. Only `dos`
templates are excluded by default (they degrade the target rather than prove a
bug); flip --nuclei-dos to include those too.
"""
from __future__ import annotations

from typing import List

from ..audit import AuditLog
from ..config import Config
from ..external import have, parse_jsonl, run
from ..utils import log
from . import Finding

# Full library: no -tags restriction. Only DoS is excluded by default (opt back in
# with --nuclei-dos) — DoS templates impair availability instead of demonstrating
# a vulnerability.
EXCLUDE_TAGS = "dos"


def _nuclei_severity(sev: str) -> str:
    sev = (sev or "").lower()
    return sev if sev in ("critical", "high", "medium", "low", "info") else "info"


def check(urls: List[str], cfg: Config, audit: AuditLog) -> List[Finding]:
    if not (cfg.use_nuclei and have("nuclei")):
        return []
    if not urls:
        return []

    log("step", f"nuclei scan ({len(urls)} targets, FULL template library)")
    # NOTE: do NOT derive nuclei's rate from --delay. --delay is the politeness
    # spacing for *our* Python requests; nuclei manages its own concurrency and
    # would crawl at ~1 req/sec over thousands of templates (hours) if we reused
    # it. nuclei gets a sane default unless the user sets --nuclei-rate.
    rl = max(1, cfg.nuclei_rate) if cfg.nuclei_rate is not None else 150
    conc = max(25, cfg.threads * 5)

    cmd = [
        "nuclei", "-jsonl", "-silent", "-disable-update-check",
        "-rate-limit", str(rl),
        "-timeout", str(int(cfg.timeout)),
        "-retries", "1",
        "-concurrency", str(conc),
        "-severity", "info,low,medium,high,critical",
    ]
    # full library by default; only DoS is held back unless explicitly opted in
    if not getattr(cfg, "nuclei_dos", False):
        cmd += ["-exclude-tags", EXCLUDE_TAGS]
    for u in urls:
        cmd += ["-u", u]

    cp = run(cmd, timeout=cfg.nuclei_timeout, audit=audit, phase="nuclei")
    if cp.returncode not in (0,) and not cp.stdout.strip():
        log("warn", f"nuclei returned no parseable output (rc={cp.returncode}). "
                    f"{(cp.stderr or '').strip()[:160]}")
        return []

    findings: List[Finding] = []
    for obj in parse_jsonl(cp.stdout):
        info = obj.get("info", {})
        sev = _nuclei_severity(info.get("severity"))
        name = info.get("name") or obj.get("template-id", "nuclei finding")
        matched = obj.get("matched-at") or obj.get("host") or ""
        tags = info.get("tags", [])
        if isinstance(tags, list):
            tags = ",".join(tags)
        findings.append(Finding(
            title=f"nuclei: {name}",
            severity=sev, category="nuclei", target=matched,
            evidence=f"template={obj.get('template-id')} tags=[{tags}] "
                     f"matched-at={matched}",
            recommendation=str(info.get("remediation")
                               or "Matched by a nuclei template (matcher-confirmed). "
                                  "Apply the template's remediation."),
            confidence="firm"))

    log("ok", f"nuclei: {len(findings)} findings")
    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {f.target}")
    return findings

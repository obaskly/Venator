"""Lightweight version-advisory heuristic.

This is NOT a full CVE database (that would need an online feed/API). It maps
fingerprinted library versions against a small built-in table of well-known
EOL/vulnerable ranges and flags them for manual confirmation. For real CVE
coverage the nuclei integration (vuln/nuclei.py) is used when available.
"""
from __future__ import annotations

from typing import List, Tuple

from ..data import VERSION_ADVISORIES
from ..utils import log
from . import Finding


def _vt(version_list) -> Tuple[int, ...]:
    return tuple(int(x) for x in version_list)


def check(fingerprint: dict) -> List[Finding]:
    findings: List[Finding] = []
    url = fingerprint.get("url", "")
    for ver in fingerprint.get("versions", []):
        tech = ver["tech"]
        try:
            vt = _vt(ver["version_tuple"])
        except Exception:
            continue
        if not vt:
            continue
        for adv_tech, predicate, note, sev in VERSION_ADVISORIES:
            if adv_tech != tech:
                continue
            try:
                if predicate(vt):
                    findings.append(Finding(
                        title=f"Outdated {tech} {ver['version']} (known issues)",
                        severity=sev, category="cve", target=url,
                        evidence=f"Detected {tech} {ver['version']}. {note}",
                        recommendation=f"Confirm exact version and upgrade {tech}; "
                                       "verify exploitability for your usage.",
                        confidence="tentative"))
            except Exception:
                continue

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {url}")
    return findings

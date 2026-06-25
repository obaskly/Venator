"""CVE -> exploitation intelligence (the 'pre-exploit' research step).

Given findings that reference CVE IDs (from nuclei or version heuristics), this
gathers, for each CVE, the context a hunter needs to *manually* assess and
reproduce impact:

  * local nuclei template metadata (description, CVSS, reference/PoC URLs),
  * `searchsploit` results if the ExploitDB CLI is installed (offline DB),
  * constructed reference links (NVD, ExploitDB, GitHub PoC search).

It never downloads or executes an exploit. Output is guidance attached to the
report as `exploit-intel` findings.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional

from ..audit import AuditLog
from ..external import have, run
from ..utils import dedup_keep_order, log
from ..vuln import Finding

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# Common nuclei-templates locations.
_TEMPLATE_DIRS = [
    os.path.expanduser("~/nuclei-templates"),
    os.path.expanduser("~/.local/nuclei-templates"),
    "/root/nuclei-templates",
]


def extract_cves(findings: List[Finding]) -> List[str]:
    cves: List[str] = []
    for f in findings:
        blob = " ".join([f.title, f.evidence, f.recommendation])
        cves.extend(m.upper() for m in CVE_RE.findall(blob))
    return dedup_keep_order(cves)


def _find_template(cve: str) -> Optional[str]:
    fname = (cve + ".yaml").upper()
    for root in _TEMPLATE_DIRS:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                if f.upper() == fname:
                    return os.path.join(dirpath, f)
    return None


def _parse_template(path: str) -> Dict[str, object]:
    """Light, dependency-free parse of the bits we care about."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return {}
    out: Dict[str, object] = {}
    m = re.search(r"^\s*description:\s*[|>]?\s*(.+)$", text, re.M)
    if m:
        out["description"] = m.group(1).strip().strip('"').strip("'")[:300]
    m = re.search(r"cvss-score:\s*([\d.]+)", text)
    if m:
        out["cvss"] = m.group(1)
    m = re.search(r"severity:\s*(\w+)", text)
    if m:
        out["severity"] = m.group(1).lower()
    refs = re.findall(r"https?://[^\s\"'\)]+", text)
    # references block tends to hold the PoC/advisory links
    out["references"] = dedup_keep_order(refs)[:8]
    return out


def _searchsploit(cve: str, audit: Optional[AuditLog]) -> List[Dict[str, str]]:
    if not have("searchsploit"):
        return []
    cp = run(["searchsploit", "--cve", cve, "-j"], timeout=30,
             audit=audit, phase="exploit-intel")
    if cp.returncode != 0 or not cp.stdout.strip():
        return []
    try:
        data = json.loads(cp.stdout)
    except json.JSONDecodeError:
        return []
    hits = []
    for e in data.get("RESULTS_EXPLOIT", []):
        hits.append({"title": e.get("Title", ""), "path": e.get("Path", ""),
                     "edb": e.get("EDB-ID", "")})
    return hits


def _reference_links(cve: str) -> List[str]:
    return [
        f"https://nvd.nist.gov/vuln/detail/{cve}",
        f"https://www.exploit-db.com/search?cve={cve}",
        f"https://github.com/search?q={cve}&type=repositories",
        f"https://www.cvedetails.com/cve/{cve}/",
    ]


def enrich(findings: List[Finding], audit: Optional[AuditLog] = None) -> List[Finding]:
    cves = extract_cves(findings)
    if not cves:
        return []
    log("step", f"CVE exploitation intel ({len(cves)} CVE(s))")
    ss_present = have("searchsploit")
    if not ss_present:
        log("info", "searchsploit not installed — using nuclei templates + "
                    "reference links (install exploitdb for offline PoC paths)")

    # map cve -> target(s) it was seen on
    cve_targets: Dict[str, List[str]] = {}
    for f in findings:
        for c in {m.upper() for m in CVE_RE.findall(f.title + f.evidence)}:
            cve_targets.setdefault(c, []).append(f.target)

    out: List[Finding] = []
    for cve in cves:
        tmpl_path = _find_template(cve)
        meta = _parse_template(tmpl_path) if tmpl_path else {}
        exploits = _searchsploit(cve, audit)
        refs = dedup_keep_order(list(meta.get("references", [])) + _reference_links(cve))

        ev_parts = []
        if meta.get("cvss"):
            ev_parts.append(f"CVSS {meta['cvss']}")
        if meta.get("description"):
            ev_parts.append(str(meta["description"]))
        if exploits:
            titles = "; ".join(f"{e['title']} (EDB-{e['edb']}, {e['path']})"
                               for e in exploits[:5])
            ev_parts.append(f"{len(exploits)} ExploitDB PoC(s): {titles}")
        else:
            ev_parts.append("no local ExploitDB PoC" +
                            ("" if ss_present else " (searchsploit not installed)"))
        ev_parts.append("refs: " + " | ".join(refs[:4]))

        sev = str(meta.get("severity") or "info")
        targets = dedup_keep_order(cve_targets.get(cve, []))
        rec = ("Reproduce impact MANUALLY against the in-scope target only. Start "
               "with the PoC/advisory links above to understand the bug class, "
               "confirm the version is actually affected, and capture a minimal "
               "non-destructive proof. Do not run mass/automated exploitation.")
        out.append(Finding(
            title=f"Exploit intel: {cve}",
            severity=sev if sev in ("critical", "high", "medium", "low", "info") else "info",
            category="exploit-intel",
            target=targets[0] if targets else "",
            evidence=" — ".join(ev_parts)[:1200],
            recommendation=rec,
            confidence="firm" if exploits else "tentative"))
        log("ok", f"{cve}: {len(exploits)} PoC(s), {len(refs)} refs"
                  + (f", template={os.path.basename(tmpl_path)}" if tmpl_path else ""))
    return out

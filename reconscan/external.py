"""Optional external tool integration (subfinder, httpx, nuclei, nmap,
masscan, openssl, dig). All are optional: if a binary is absent the relevant
module degrades to a pure-Python fallback.

External tools are also recorded in the audit log (as a single line noting the
command), since they generate their own network traffic.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import List, Optional

from .audit import AuditLog
from .utils import log


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def detect() -> dict:
    tools = ["subfinder", "httpx", "nuclei", "nmap", "masscan",
             "openssl", "dig", "whois", "curl", "katana"]
    return {t: have(t) for t in tools}


def run(cmd: List[str], *, timeout: int = 600,
        audit: Optional[AuditLog] = None, phase: str = "external") -> subprocess.CompletedProcess:
    if audit:
        audit.record("EXEC", " ".join(cmd), phase=phase, tool=cmd[0],
                     note="external tool invocation")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "not found")
    try:
        out, err = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(cmd, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        # Kill but KEEP whatever the tool produced so far (important for nuclei
        # under a long template run that exceeds the timeout).
        proc.kill()
        out, err = proc.communicate()
        log("warn", f"external tool timed out: {cmd[0]} (kept partial output, "
                    f"{len(out or '')} bytes)")
        return subprocess.CompletedProcess(cmd, 124, out or "", err or "timeout")


def parse_jsonl(text: str) -> List[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out

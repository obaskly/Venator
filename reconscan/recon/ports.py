"""Port scanning of discovered live hosts.

Prefers nmap (if installed) for a polite, timed scan; otherwise uses a
pure-Python threaded TCP connect scan. Default port set is small and common
(no DoS-scale sweeps). Note: hosts behind a CDN/WAF (Cloudflare etc.) will
show the edge's ports, not the origin — this is expected and flagged.
"""
from __future__ import annotations

import concurrent.futures as cf
import socket
from typing import Dict, List

from ..audit import AuditLog
from ..config import Config
from ..external import have, run
from ..utils import log


def _nmap(host: str, ports: List[int], audit: AuditLog, timeout_s: float) -> List[dict]:
    port_arg = ",".join(str(p) for p in ports)
    # -T2 polite timing, -Pn (we already know it's live), service/version detect
    cmd = ["nmap", "-Pn", "-T2", "-sV", "--version-light",
           "-p", port_arg, "--host-timeout", "120s", "-oG", "-", host]
    cp = run(cmd, timeout=300, audit=audit, phase="ports")
    open_ports: List[dict] = []
    # Parse greppable output: "Ports: 80/open/tcp//http//Apache, 443/open/..."
    for line in cp.stdout.splitlines():
        if "Ports:" not in line:
            continue
        seg = line.split("Ports:", 1)[1]
        for entry in seg.split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 5 and parts[1] == "open":
                open_ports.append({
                    "port": int(parts[0]),
                    "proto": parts[2],
                    "service": parts[4] or "",
                    "version": (parts[6] if len(parts) > 6 else "").strip(),
                })
    return open_ports


def _connect_scan(host: str, ports: List[int], threads: int, timeout_s: float) -> List[dict]:
    open_ports: List[dict] = []

    def probe(port: int):
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as s:
                svc = ""
                try:
                    svc = socket.getservbyport(port)
                except OSError:
                    pass
                return {"port": port, "proto": "tcp", "service": svc, "version": ""}
        except OSError:
            return None

    with cf.ThreadPoolExecutor(max_workers=max(4, threads)) as ex:
        for res in ex.map(probe, ports):
            if res:
                open_ports.append(res)
    return open_ports


def scan_host(host: str, cfg: Config, audit: AuditLog) -> List[dict]:
    if cfg.use_external and have("nmap"):
        ports = _nmap(host, cfg.ports, audit, cfg.timeout)
    else:
        audit.record("PORTSCAN", f"tcp://{host}", phase="ports",
                     note=f"python connect scan {len(cfg.ports)} ports")
        ports = _connect_scan(host, cfg.ports, cfg.threads, cfg.timeout)
    for p in sorted(ports, key=lambda x: x["port"]):
        extra = f" {p['service']} {p['version']}".rstrip()
        log("ok", f"{host}:{p['port']} open{extra}")
    return sorted(ports, key=lambda x: x["port"])


def scan(live_hosts: List[str], cfg: Config, audit: AuditLog) -> Dict[str, List[dict]]:
    log("step", f"Port scan ({len(live_hosts)} hosts, {len(cfg.ports)} ports each)")
    results: Dict[str, List[dict]] = {}
    for host in live_hosts:
        results[host] = scan_host(host, cfg, audit)
    return results

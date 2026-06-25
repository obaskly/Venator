"""Structured report output: JSON (machine), Markdown (LLM), HTML (human)."""
from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import Dict, List

from ..utils import log
from ..vuln import SEVERITY_ORDER, sort_findings

SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
             "low": "LOW", "info": "INFO"}
SEV_COLOR = {"critical": "#ff2d55", "high": "#ff6b35", "medium": "#ffb020",
             "low": "#3da5ff", "info": "#8a93a6"}


def _canon(url: str) -> str:
    from urllib.parse import urlparse
    pr = urlparse(url)
    return f"{pr.scheme}://{pr.netloc}{(pr.path or '').rstrip('/')}"


def _split_services(probes: List[dict]):
    """Return (in_scope_services, offscope_redirectors).

    In-scope services are deduped by canonical final URL (collapses www<->apex
    and trailing slash); off-scope redirectors (mail host -> 3rd-party SSO) are
    deduped by request host and listed separately so the report never presents a
    third-party asset as one of the target's services."""
    in_scope: Dict[str, dict] = {}
    offscope: Dict[str, dict] = {}
    for p in probes:
        clean = {k: v for k, v in p.items() if k != "_body"}
        if p.get("final_host_in_scope", True):
            key = _canon(p.get("final_url") or p.get("url"))
            cur = in_scope.get(key)
            if cur is None or (p.get("scheme") == "https" and cur.get("scheme") != "https"):
                in_scope[key] = clean
        else:
            from urllib.parse import urlparse
            host = urlparse(p.get("url", "")).netloc
            if host not in offscope or p.get("scheme") == "https":
                offscope[host] = clean
    return list(in_scope.values()), list(offscope.values())


def build(meta: dict, recon: dict, findings, audit_count: int,
          hunts=None) -> dict:
    findings = sort_findings(findings)
    sev_counts: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    http_services, offscope_redirectors = _split_services(recon.get("probes", []))
    n_exploit = sum(1 for f in findings if f.category == "exploit")
    n_chain = sum(1 for f in findings if f.category == "chain")

    return {
        "meta": meta,
        "summary": {
            "total_findings": len(findings),
            "by_severity": sev_counts,
            "subdomains_total": len(recon.get("subdomains", [])),
            "subdomains_live": sum(1 for s in recon.get("subdomains", []) if s.get("live")),
            "http_services": len(http_services),
            "offscope_redirectors": len(offscope_redirectors),
            "confirmed_exploits": n_exploit,
            "chains": n_chain,
            "audit_requests_logged": audit_count,
            "triage": meta.get("triage", {}),
        },
        "top_hunts": hunts or [],
        "recon": {
            "subdomains": recon.get("subdomains", []),
            "dns_records": recon.get("dns_records", {}),
            "ports": recon.get("ports", {}),
            "http_services": http_services,
            "offscope_redirectors": offscope_redirectors,
            "fingerprints": recon.get("fingerprints", []),
            "endpoints": recon.get("endpoints", []),
            "favicon": recon.get("favicon", []),
            "jsintel": recon.get("jsintel", {}),
            "crawl": recon.get("crawl", {}),
            "browser": recon.get("browser", {}),
            "wayback": recon.get("wayback", {}),
            "oob": recon.get("oob", {}),
        },
        "findings": [f.to_dict() for f in findings],
        "filtered_findings": recon.get("filtered_findings", []),
    }


def write_json(report: dict, output_dir: str) -> str:
    path = os.path.join(output_dir, "report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    return path


def root_name(apex: str) -> str:
    """Registrable-ish report folder: example.com -> example, example.com:8080 ->
    example_8080. IP / single-label hosts keep the FULL host plus port so that
    distinct host:port targets never collide (127.0.0.1:3000 vs 127.0.0.1:8888
    used to both fold to '0' and overwrite each other's report)."""
    import ipaddress
    raw = (apex or "").split("://")[-1].split("/")[0]
    host = raw.split(":")[0]
    port = raw.split(":", 1)[1] if ":" in raw else ""
    labels = [l for l in host.split(".") if l]
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    if is_ip or len(labels) < 2:
        base = host.replace(".", "_") or (apex or "target")
    else:
        base = labels[-2]
    return f"{base}_{port}" if port else base


def write_summary(report: dict, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    m = report["meta"]
    s = report["summary"]
    lines: List[str] = []
    A = lines.append

    A(f"# reconscan report — {m.get('target')}")
    A("")
    A(f"- Scan start: {m.get('started')}")
    A(f"- Scan end:   {m.get('finished')}")
    A(f"- Duration:   {m.get('duration_s')}s")
    A(f"- Requests logged (audit): {s.get('audit_requests_logged')}")
    A(f"- External tools available: {', '.join(k for k,v in m.get('tools',{}).items() if v) or 'none'}")
    A("")
    A("> Authorized testing only. This run actively **confirms** vulnerabilities "
      "with proof-of-concept (proof-over-damage: it extracts a minimal indicator, "
      "never dumps or destroys data). `confirmed`/EXPLOITED findings carry a PoC; "
      "everything else is a candidate — confirm manually before reporting.")
    A("")

    warns = m.get("warnings", [])
    if warns:
        A("## ⚠ Run warnings")
        A("")
        for w in warns:
            A(f"- {w}")
        A("")

    A("## Summary")
    A("")
    A(f"- Subdomains: {s['subdomains_live']} live / {s['subdomains_total']} total")
    A(f"- HTTP services probed: {s['http_services']}")
    A(f"- **Confirmed exploits: {s.get('confirmed_exploits',0)}** · "
      f"**Attack chains: {s.get('chains',0)}**")
    A(f"- Findings: {s['total_findings']}")
    bs = s["by_severity"]
    A(f"  - CRITICAL {bs.get('critical',0)} | HIGH {bs.get('high',0)} | "
      f"MEDIUM {bs.get('medium',0)} | LOW {bs.get('low',0)} | INFO {bs.get('info',0)}")
    tri = s.get("triage") or {}
    if tri:
        A(f"- Triage: {tri.get('reconfirmed',0)} re-confirmed, "
          f"{tri.get('filtered_false_positive',0)} false positives filtered, "
          f"{tri.get('duplicates_removed',0)} duplicates removed")
    oob = report.get("recon", {}).get("oob") or {}
    if oob.get("domain"):
        A(f"- OOB collaborator: {oob.get('provider')} ({oob.get('domain')}, "
          f"DNS={'yes' if oob.get('dns_capable') else 'no'}) — blind SSRF/RCE/XXE/XSS armed")
    jsi = report.get("recon", {}).get("jsintel") or {}
    if jsi.get("source_maps_recovered"):
        A(f"- JS source maps recovered: {jsi.get('source_maps_recovered')} "
          "(original source mined for secrets/endpoints)")
    A("")

    # top hunts (ranked by bounty potential)
    hunts = report.get("top_hunts", [])
    if hunts:
        A("## 🎯 Hunt these first")
        A("")
        A("_Ranked by bounty potential (severity + exploitability + asset value)._")
        A("")
        for h in hunts:
            vflag = {True: "✓confirmed", False: "✗fp", None: "?unverified"}.get(h.get("validated"))
            A(f"1. **[{h['severity'].upper()}] {h['title']}** "
              f"(score {h.get('priority',0)}, {vflag})")
            A(f"   - `{h['target']}`")
        A("")

    # findings
    A("## Findings")
    A("")
    if not report["findings"]:
        A("_No findings._")
    else:
        cur_sev = None
        for f in report["findings"]:
            if f["severity"] != cur_sev:
                cur_sev = f["severity"]
                A(f"### {SEV_LABEL.get(cur_sev, cur_sev.upper())}")
                A("")
            vflag = {True: "✓ re-confirmed", False: "✗ likely FP",
                     None: "? unverified"}.get(f.get("validated"))
            A(f"- **{f['title']}** ({f['category']}, {f['confidence']}, "
              f"priority {f.get('priority',0)}, {vflag})")
            A(f"  - Target: `{f['target']}`")
            A(f"  - Evidence: {f['evidence']}")
            if f.get("fp_note"):
                A(f"  - Validation: {f['fp_note']}")
            if f.get("poc"):
                A(f"  - PoC: `{f['poc']}`")
            A(f"  - Next step: {f['recommendation']}")
            A("")

    # recon detail
    A("## Recon detail")
    A("")
    A("### Live subdomains")
    live = [x for x in report["recon"]["subdomains"] if x.get("live")]
    if live:
        for sd in live:
            A(f"- `{sd['host']}` -> {', '.join(sd['addresses'])}")
    else:
        A("_none_")
    A("")

    A("### DNS records")
    dns = report["recon"]["dns_records"]
    if dns:
        for rtype, vals in dns.items():
            for v in vals:
                A(f"- {rtype}: `{v}`")
    else:
        A("_none_")
    A("")

    A("### Open ports")
    ports = report["recon"]["ports"]
    any_port = False
    for host, plist in ports.items():
        for p in plist:
            any_port = True
            A(f"- `{host}:{p['port']}` {p.get('service','')} {p.get('version','')}".rstrip())
    if not any_port:
        A("_none open / all filtered (expected behind CDN/WAF)_")
    A("")

    A("### HTTP services (in scope)")
    for svc in report["recon"]["http_services"]:
        A(f"- [{svc['status']}] `{svc['final_url']}` — "
          f"{svc.get('server','-')} — \"{svc.get('title','')[:60]}\"")
    A("")

    redirs = report["recon"].get("offscope_redirectors", [])
    if redirs:
        A("### Off-scope redirectors (NOT scanned)")
        A("")
        A("_These in-scope hosts redirect to third-party services. They were "
          "detected but never probed/fingerprinted — out of scope._")
        for svc in redirs:
            A(f"- [{svc['status']}] `{svc['url']}` -> `{svc['final_url']}`")
        A("")

    A("### Technologies")
    for fp in report["recon"]["fingerprints"]:
        techs = ", ".join(fp.get("technologies", []))
        vers = ", ".join(f"{v['tech']}={v['version']}" for v in fp.get("versions", []))
        if techs or vers:
            A(f"- `{fp['url']}`: {techs}" + (f" | {vers}" if vers else ""))
    A("")

    # favicon hash pivots
    favs = report["recon"].get("favicon", [])
    if favs:
        A("### Favicon hashes (Shodan/FOFA pivot)")
        for fv in favs:
            A(f"- `{fv.get('base_url','')}`: mmh3 `{fv.get('hash')}` "
              f"— Shodan: {fv.get('shodan','')}")
        A("")

    # JS intelligence
    js = report["recon"].get("jsintel") or {}
    if js:
        A("### JS intelligence")
        A(f"- Scripts analyzed: {js.get('scripts_analyzed',0)}")
        A(f"- Secret candidates: {js.get('secret_candidates',0)}")
        eps = js.get("endpoints", [])
        if eps:
            A(f"- Endpoints extracted ({len(eps)}):")
            for e in eps[:40]:
                A(f"  - `{e}`")
        A("")

    # Wayback historical mining
    wb = report["recon"].get("wayback") or {}
    if wb:
        A("### Historical URLs (Wayback/CDX)")
        A(f"- Archived: {wb.get('total',0)} | in-scope: {wb.get('in_scope',0)} | "
          f"juicy: {wb.get('juicy',0)}")
        for u in (wb.get("juicy_urls") or [])[:30]:
            A(f"  - `{u}`")
        A("")

    # filtered false positives (transparency)
    filt = report.get("filtered_findings", [])
    if filt:
        A("### Filtered (likely false positives)")
        A("")
        for f in filt:
            A(f"- ~~{f['title']}~~ @ `{f['target']}` — {f.get('fp_note','')}")
        A("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def _bar(label: str, count: int, total: int, color: str) -> str:
    pct = (count / total * 100) if total else 0
    return (f'<div class="bar-row"><span class="bar-label">{html.escape(label)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width:{pct:.1f}%;'
            f'background:{color}"></span></span>'
            f'<span class="bar-count">{count}</span></div>')


def _finding_card(f: dict) -> str:
    e = html.escape
    sev = f.get("severity", "info")
    color = SEV_COLOR.get(sev, "#8a93a6")
    vmap = {True: ("✓ re-confirmed", "#23d18b"), False: ("✗ likely FP", "#ff6b35"),
            None: ("? manual", "#8a93a6")}
    vtxt, vcol = vmap.get(f.get("validated"))
    note = (f'<div class="kv"><b>Validation</b>{e(f.get("fp_note",""))}</div>'
            if f.get("fp_note") else "")
    poc = (f'<div class="poc"><span class="poc-lbl">PoC</span>'
           f'<code class="poc-code">{e(f.get("poc",""))}</code>'
           f'<button class="copy" onclick="cp(this)">copy</button></div>'
           if f.get("poc") else "")
    return f"""
    <div class="card" data-sev="{sev}">
      <div class="card-head">
        <span class="sev-badge" style="background:{color}">{SEV_LABEL.get(sev, sev.upper())}</span>
        <span class="card-title">{e(f.get('title',''))}</span>
        <span class="score-chip" title="bounty priority">★ {f.get('priority',0)}</span>
      </div>
      <div class="card-meta">
        <span class="tag">{e(f.get('category',''))}</span>
        <span class="tag">{e(f.get('confidence',''))}</span>
        <span class="tag" style="color:{vcol}">{vtxt}</span>
      </div>
      <div class="kv"><b>Target</b><code>{e(str(f.get('target','')))}</code></div>
      <div class="kv"><b>Evidence</b>{e(str(f.get('evidence','')))}</div>
      {note}
      {poc}
      <div class="kv"><b>Next step</b>{e(str(f.get('recommendation','')))}</div>
    </div>"""


def write_html(report: dict, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    e = html.escape
    m = report["meta"]
    s = report["summary"]
    bs = s["by_severity"]
    rec = report["recon"]
    total_f = s["total_findings"] or 1

    # severity bars
    bars = "".join(_bar(SEV_LABEL[k], bs.get(k, 0), s["total_findings"] or 1, SEV_COLOR[k])
                   for k in ("critical", "high", "medium", "low", "info"))

    # summary stat cards
    crit_high = bs.get("critical", 0) + bs.get("high", 0)
    stats = [
        ("Findings", s["total_findings"], "#7c5cff"),
        ("Crit+High", crit_high, "#ff2d55"),
        ("Exploited", s.get("confirmed_exploits", 0), "#ff2d55"),
        ("Chains", s.get("chains", 0), "#ff6b35"),
        ("Live subdomains", s["subdomains_live"], "#23d18b"),
        ("HTTP services", s["http_services"], "#3da5ff"),
        ("Requests", s["audit_requests_logged"], "#8a93a6"),
    ]
    stat_html = "".join(
        f'<div class="stat"><div class="stat-num" style="color:{c}">{v}</div>'
        f'<div class="stat-lbl">{e(l)}</div></div>' for l, v, c in stats)

    # warnings
    warns = m.get("warnings", [])
    warn_html = ""
    if warns:
        items = "".join(f"<li>{e(w)}</li>" for w in warns)
        warn_html = f'<div class="warn-box"><b>⚠ Run warnings</b><ul>{items}</ul></div>'

    # top hunts
    hunts = report.get("top_hunts", [])
    hunt_html = ""
    if hunts:
        rows = ""
        for i, h in enumerate(hunts, 1):
            c = SEV_COLOR.get(h.get("severity", "info"), "#8a93a6")
            rows += (f'<div class="hunt"><span class="rank">{i}</span>'
                     f'<span class="sev-dot" style="background:{c}"></span>'
                     f'<span class="hunt-title">{e(h.get("title",""))}</span>'
                     f'<span class="hunt-score">★ {h.get("priority",0)}</span>'
                     f'<code class="hunt-tgt">{e(str(h.get("target","")))}</code></div>')
        hunt_html = f'<section><h2>🎯 Hunt these first</h2><div class="hunts">{rows}</div></section>'

    # findings
    findings = report.get("findings", [])
    find_html = "".join(_finding_card(f) for f in findings) or \
        '<p class="muted">No findings.</p>'

    # recon: subdomains
    subs = [x for x in rec.get("subdomains", []) if x.get("live")]
    sub_rows = "".join(f"<tr><td><code>{e(x['host'])}</code></td>"
                       f"<td>{e(', '.join(x.get('addresses', [])[:4]))}</td></tr>"
                       for x in subs) or '<tr><td colspan=2 class="muted">none</td></tr>'

    # http services
    svc_rows = "".join(
        f"<tr><td>{e(str(svc.get('status')))}</td><td><code>{e(svc.get('final_url',''))}</code></td>"
        f"<td>{e(svc.get('server','-'))}</td><td>{e((svc.get('title','') or '')[:60])}</td></tr>"
        for svc in rec.get("http_services", [])) or '<tr><td colspan=4 class="muted">none</td></tr>'

    # off-scope redirectors
    redir = rec.get("offscope_redirectors", [])
    redir_html = ""
    if redir:
        rows = "".join(f"<tr><td>{e(str(x.get('status')))}</td>"
                       f"<td><code>{e(x.get('url',''))}</code> → <code>{e(x.get('final_url',''))}</code></td></tr>"
                       for x in redir)
        redir_html = (f'<section><h2>Off-scope redirectors '
                      f'<span class="muted">(NOT scanned)</span></h2>'
                      f'<table><tbody>{rows}</tbody></table></section>')

    # technologies
    tech_rows = ""
    for fpr in rec.get("fingerprints", []):
        techs = ", ".join(fpr.get("technologies", []))
        vers = ", ".join(f"{v['tech']}={v['version']}" for v in fpr.get("versions", []))
        if techs or vers:
            tech_rows += (f"<tr><td><code>{e(fpr['url'])}</code></td>"
                          f"<td>{e(techs)}{(' | ' + e(vers)) if vers else ''}</td></tr>")
    tech_rows = tech_rows or '<tr><td colspan=2 class="muted">none</td></tr>'

    # favicon
    favs = rec.get("favicon", [])
    fav_html = ""
    if favs:
        rows = "".join(f'<tr><td><code>{e(x.get("base_url",""))}</code></td>'
                       f'<td><code>{e(str(x.get("hash")))}</code></td>'
                       f'<td><a href="{e(x.get("shodan",""))}" target="_blank">Shodan pivot ↗</a></td></tr>'
                       for x in favs)
        fav_html = (f'<section><h2>Favicon hash <span class="muted">(pivot to find sibling hosts)</span></h2>'
                    f'<table><thead><tr><th>Service</th><th>mmh3</th><th>Pivot</th></tr></thead>'
                    f'<tbody>{rows}</tbody></table></section>')

    # JS intel
    js = rec.get("jsintel") or {}
    js_html = ""
    if js:
        eps = "".join(f"<li><code>{e(x)}</code></li>" for x in js.get("endpoints", [])[:60])
        js_html = (f'<section><h2>JS intelligence</h2>'
                   f'<p>Scripts analyzed: <b>{js.get("scripts_analyzed",0)}</b> · '
                   f'Secret candidates: <b>{js.get("secret_candidates",0)}</b></p>'
                   f'<ul class="eps">{eps}</ul></section>')

    # wayback
    wb = rec.get("wayback") or {}
    wb_html = ""
    if wb:
        jus = "".join(f"<li><code>{e(u)}</code></li>" for u in (wb.get("juicy_urls") or [])[:40])
        wb_html = (f'<section><h2>Historical URLs (Wayback)</h2>'
                   f'<p>Archived <b>{wb.get("total",0)}</b> · in-scope <b>{wb.get("in_scope",0)}</b> · '
                   f'juicy <b>{wb.get("juicy",0)}</b></p><ul class="eps">{jus}</ul></section>')

    # dns
    dns_rows = ""
    for rtype, vals in (rec.get("dns_records") or {}).items():
        for v in vals:
            dns_rows += f"<tr><td>{e(rtype)}</td><td><code>{e(v)}</code></td></tr>"
    dns_rows = dns_rows or '<tr><td colspan=2 class="muted">none</td></tr>'

    tri = s.get("triage") or {}
    tri_line = ""
    if tri:
        tri_line = (f'<p class="muted">Triage: {tri.get("reconfirmed",0)} re-confirmed · '
                    f'{tri.get("filtered_false_positive",0)} FP filtered · '
                    f'{tri.get("duplicates_removed",0)} dupes removed</p>')

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>reconscan — {e(m.get('target',''))}</title>
<style>
:root{{--bg:#0b0e14;--panel:#141925;--panel2:#1b2230;--line:#263043;--txt:#e6e9ef;--muted:#8a93a6;--accent:#7c5cff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#bcd}}
a{{color:#6ab0ff}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 80px}}
header{{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:24px}}
header h1{{margin:0;font-size:22px;letter-spacing:.3px}}
header h1 .dot{{color:var(--accent)}}
.sub{{color:var(--muted);font-size:12.5px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:22px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;text-align:center}}
.stat-num{{font-size:26px;font-weight:700}}
.stat-lbl{{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:18px}}
h2{{font-size:15px;margin:0 0 14px;letter-spacing:.3px}}
.bars{{display:flex;flex-direction:column;gap:8px;max-width:520px}}
.bar-row{{display:flex;align-items:center;gap:10px}}
.bar-label{{width:74px;color:var(--muted);font-size:12px}}
.bar-track{{flex:1;height:9px;background:var(--panel2);border-radius:6px;overflow:hidden}}
.bar-fill{{display:block;height:100%}}
.bar-count{{width:26px;text-align:right;font-variant-numeric:tabular-nums}}
.hunts{{display:flex;flex-direction:column;gap:8px}}
.hunt{{display:flex;align-items:center;gap:10px;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:9px 12px}}
.rank{{width:20px;height:20px;border-radius:50%;background:var(--accent);color:#fff;font-size:12px;display:flex;align-items:center;justify-content:center;flex:0 0 auto}}
.sev-dot{{width:9px;height:9px;border-radius:50%;flex:0 0 auto}}
.hunt-title{{font-weight:600}}
.hunt-score{{color:#ffb020;font-size:12px}}
.hunt-tgt{{margin-left:auto;color:var(--muted);max-width:46%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.filters{{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}}
.fbtn{{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:20px;padding:5px 13px;cursor:pointer;font-size:12.5px}}
.fbtn.active{{background:var(--accent);border-color:var(--accent);color:#fff}}
.card{{background:var(--panel2);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.card-head{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.sev-badge{{font-size:10.5px;font-weight:700;color:#0b0e14;padding:2px 8px;border-radius:5px;letter-spacing:.4px}}
.card-title{{font-weight:600;font-size:14.5px}}
.score-chip{{margin-left:auto;color:#ffb020;font-size:12px}}
.card-meta{{display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap}}
.tag{{background:#0e1320;border:1px solid var(--line);color:var(--muted);border-radius:6px;padding:1px 8px;font-size:11px}}
.kv{{font-size:13px;margin:5px 0;color:#cdd3df}}
.kv b{{display:inline-block;min-width:84px;color:var(--muted);font-weight:600}}
.poc{{display:flex;align-items:center;gap:8px;margin:8px 0;background:#0a0d16;border:1px solid var(--line);border-radius:8px;padding:8px 10px}}
.poc-lbl{{color:#23d18b;font-size:10.5px;font-weight:700;letter-spacing:.5px;flex:0 0 auto}}
.poc-code{{flex:1;color:#9fe6c0;overflow-x:auto;white-space:nowrap}}
.copy{{flex:0 0 auto;background:var(--accent);border:0;color:#fff;border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer}}
.copy.done{{background:#23d18b}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.4px}}
.eps{{columns:2;gap:24px;margin:0;padding-left:18px}}
.eps li{{margin:2px 0}}
.muted{{color:var(--muted)}}
.warn-box{{background:#2a1f12;border:1px solid #5a3d1a;border-radius:12px;padding:12px 16px;margin-bottom:18px;color:#ffce8a}}
.warn-box ul{{margin:6px 0 0;padding-left:18px}}
footer{{color:var(--muted);font-size:11.5px;text-align:center;margin-top:30px}}
</style></head><body><div class="wrap">
<header>
  <div><h1>recon<span class="dot">scan</span> · {e(m.get('target',''))}</h1>
  <div class="sub">{e(str(m.get('started','')))} → {e(str(m.get('finished','')))} · {e(str(m.get('duration_s','')))}s · v{e(str(m.get('version','')))}</div></div>
  <div class="sub">non-destructive · authorized testing only</div>
</header>
{warn_html}
<div class="stats">{stat_html}</div>
<section><h2>Severity breakdown</h2><div class="bars">{bars}</div>{tri_line}</section>
{hunt_html}
<section><h2>Findings ({s['total_findings']})</h2>
<div class="filters">
  <button class="fbtn active" data-f="all">All</button>
  <button class="fbtn" data-f="critical">Critical</button>
  <button class="fbtn" data-f="high">High</button>
  <button class="fbtn" data-f="medium">Medium</button>
  <button class="fbtn" data-f="low">Low</button>
  <button class="fbtn" data-f="info">Info</button>
</div>
<div id="findings">{find_html}</div></section>
{fav_html}
<section><h2>Technologies</h2><table><tbody>{tech_rows}</tbody></table></section>
{js_html}
{wb_html}
<section><h2>Live subdomains</h2><table><thead><tr><th>Host</th><th>Addresses</th></tr></thead><tbody>{sub_rows}</tbody></table></section>
<section><h2>HTTP services (in scope)</h2><table><thead><tr><th>Status</th><th>URL</th><th>Server</th><th>Title</th></tr></thead><tbody>{svc_rows}</tbody></table></section>
{redir_html}
<section><h2>DNS records</h2><table><tbody>{dns_rows}</tbody></table></section>
<footer>Generated by reconscan · findings are candidates — confirm manually before action</footer>
</div>
<script>
function cp(b){{const c=b.previousElementSibling.innerText;navigator.clipboard&&navigator.clipboard.writeText(c);b.textContent='copied';b.classList.add('done');setTimeout(()=>{{b.textContent='copy';b.classList.remove('done')}},1200);}}
const btns=document.querySelectorAll('.fbtn');
btns.forEach(b=>b.onclick=()=>{{
  btns.forEach(x=>x.classList.remove('active'));b.classList.add('active');
  const f=b.dataset.f;
  document.querySelectorAll('#findings .card').forEach(c=>{{
    c.style.display=(f==='all'||c.dataset.sev===f)?'':'none';
  }});
}});
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def emit(report: dict, output_dir: str, target: str) -> Dict[str, str]:
    jp = write_json(report, output_dir)
    root = root_name(target)
    # Markdown for an AI/LLM; HTML dashboard for the human.
    md_path = os.path.join("reports", root, "scan_report.md")
    html_path = os.path.join("reports", root, "scan_report.html")
    mp = write_summary(report, md_path)
    hp = write_html(report, html_path)
    log("ok", f"report (JSON):     {jp}")
    log("ok", f"report (markdown): {mp}")
    log("ok", f"report (HTML):     {hp}")
    return {"json": jp, "summary": mp, "html": hp, "report_dir": os.path.dirname(md_path)}

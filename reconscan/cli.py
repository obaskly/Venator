"""Command-line entry point and phase orchestration."""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from typing import Dict, List

from . import __version__
from . import browser as browserphase
from .audit import AuditLog
from .config import Config, DEFAULT_PORTS
from .external import detect
from .http import Client
from .utils import Scope, log, dedup_keep_order, is_catch_all_artifact
from .oob import OOBClient
from .recon import dns_records, subdomains, ports as portscan, probe as prober, \
    fingerprint as fp, endpoints as endp, jsintel, wayback, takeover, favicon, \
    apispec, crawler
from .vuln import headers as vheaders, tls as vtls, misconfig as vmisc, \
    cors as vcors, reflection as vrefl, cve as vcve, nuclei as vnuclei, \
    graphql as vgraphql, nextjs as vnextjs, cache as vcache, email_sec as vemail, \
    dataleak as vdataleak, smuggling as vsmuggling, wcd as vwcd, waf as vwaf, \
    exposure as vexposure, Finding
from .intel import cve as cveintel
from .active import run_active
from .exploit import run_exploit
from .chain import build_chains
from .validate import validator
from .score import prioritize, top_hunts
from .report import report as reporter
from .utils import set_verbosity
from .active import hpp as ahpp


BANNER = r"""
  reconscan v{ver} — authorized recon + exploitation + chaining
  ---------------------------------------------------------------------
""".format(ver=__version__)

LEGAL = ("USE ONLY against systems you own or are explicitly authorized to test.\n"
         "This tool actively CONFIRMS vulnerabilities with proof-of-concept\n"
         "(proof-over-damage: minimal indicator only, never dumps/destroys data).\n"
         "Gate offensive phases with --no-exploit/--no-chain/--no-active if needed.\n"
         "Every request is rate-limited and logged to the audit file.")


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="reconscan",
        description="Authorized-use recon + non-destructive vulnerability detection.")
    p.add_argument("target", help="apex domain to scan (e.g. example.com)")
    p.add_argument("-o", "--output", default=None,
                   help="output dir (default: output/<target>)")

    g = p.add_argument_group("politeness / safety")
    g.add_argument("--delay", type=float, default=1.0,
                   help="seconds between requests (default 1.0)")
    g.add_argument("--rate-limit", type=float, default=None,
                   help="max requests/sec (alternative to --delay)")
    g.add_argument("--timeout", type=float, default=10.0, help="per-request timeout")
    g.add_argument("--threads", type=int, default=5, help="per-phase HTTP concurrency cap")
    g.add_argument("--workers", type=int, default=0,
                   help="parallel phase workers (0=auto from CPU count). Overlaps "
                        "independent work (nuclei/nmap/wayback/DNS); target HTTP "
                        "rate stays bounded by --delay for politeness")
    g.add_argument("--verify-tls", action="store_true",
                   help="verify TLS certs on HTTP requests")
    g.add_argument("--no-rotate-ua", action="store_true",
                   help="disable per-request random User-Agent rotation")
    g.add_argument("-y", "--yes", action="store_true",
                   help="skip the interactive authorization confirmation")
    g.add_argument("--extra-scope", default="",
                   help="comma-separated extra in-scope hosts you own")
    g.add_argument("-q", "--quiet", action="store_true",
                   help="quiet output (summaries only) — good for many subdomains")
    g.add_argument("-v", "--verbose", action="store_true",
                   help="verbose output (per-request detail, blocked hosts)")

    au = p.add_argument_group("authenticated scanning (most bugs sit behind login)")
    au.add_argument("--cookie", default="",
                    help="session cookie(s) to send on every request, e.g. "
                         "\"session=abc; csrf=xyz\"")
    au.add_argument("--auth-bearer", default="",
                    help="bearer token -> 'Authorization: Bearer <token>' on every request")
    au.add_argument("--header", action="append", default=[], metavar="K: V",
                    help="extra header sent on every request (repeatable)")

    ob = p.add_argument_group("out-of-band (OOB) — confirm BLIND bugs")
    ob.add_argument("--no-oob", action="store_true",
                    help="disable the OOB collaborator (blind SSRF/RCE/XXE/XSS off)")
    ob.add_argument("--oob-provider", default="auto",
                    choices=["auto", "interactsh", "ngrok"],
                    help="OOB backend (default auto: interactsh, else ngrok)")
    ob.add_argument("--ngrok-domain", default="",
                    help="reserved ngrok domain for the OOB fallback "
                         "(e.g. hermit-alert-freely.ngrok-free.app)")

    ph = p.add_argument_group("phase toggles")
    ph.add_argument("--no-subdomains", action="store_true")
    ph.add_argument("--no-dns", action="store_true")
    ph.add_argument("--no-ports", action="store_true")
    ph.add_argument("--no-probe", action="store_true")
    ph.add_argument("--no-fingerprint", action="store_true")
    ph.add_argument("--no-endpoints", action="store_true")
    ph.add_argument("--no-vuln", action="store_true")
    ph.add_argument("--no-nuclei", action="store_true")
    ph.add_argument("--no-external", action="store_true",
                    help="ignore external tools (pure-Python fallbacks)")
    ph.add_argument("--no-dir-brute", action="store_true",
                    help="skip wordlist directory probing")
    ph.add_argument("--no-jsintel", action="store_true",
                    help="skip JS endpoint + secret mining")
    ph.add_argument("--no-crawl", action="store_true",
                    help="skip the recursive in-scope crawler (surface expansion)")
    ph.add_argument("--no-katana", action="store_true",
                    help="don't use the katana binary as a crawl accelerator")
    ph.add_argument("--no-exposure", action="store_true",
                    help="skip .git/actuator/.env exposure extraction")
    ph.add_argument("--no-oauth", action="store_true",
                    help="skip OAuth/OIDC redirect_uri + flow checks")
    ph.add_argument("--no-browser", action="store_true",
                    help="skip the headless-browser phase (SPA render + DOM-XSS)")
    ph.add_argument("--no-wayback", action="store_true",
                    help="skip Wayback/CDX historical URL mining")
    ph.add_argument("--no-takeover", action="store_true",
                    help="skip subdomain takeover checks")
    ph.add_argument("--no-graphql", action="store_true",
                    help="skip GraphQL introspection check")
    ph.add_argument("--no-validate", action="store_true",
                    help="skip the false-positive filtering / validation pass")
    ph.add_argument("--no-cve-intel", action="store_true",
                    help="skip CVE -> exploitation intelligence enrichment")
    ph.add_argument("--no-active", action="store_true",
                    help="skip active probing (403 bypass / open-redirect / "
                         "error-based injection leads)")
    ph.add_argument("--no-exploit", action="store_true",
                    help="skip the exploitation phase (confirm + PoC)")
    ph.add_argument("--no-chain", action="store_true",
                    help="skip the exploit-chaining engine")
    ph.add_argument("--no-apispec", action="store_true",
                    help="skip OpenAPI/Swagger ingestion")
    ph.add_argument("--no-parammine", action="store_true",
                    help="skip hidden-parameter discovery (Arjun-style)")
    ph.add_argument("--no-sourcemap", action="store_true",
                    help="skip JS source-map recovery + DOM-sink mining")
    ph.add_argument("--no-blindxss", action="store_true",
                    help="skip planting blind/stored XSS OOB callbacks")
    ph.add_argument("--no-race", action="store_true",
                    help="skip race-condition detection")
    ph.add_argument("--no-protopollution", action="store_true",
                    help="skip prototype pollution detection")
    ph.add_argument("--no-log4shell", action="store_true",
                    help="skip Log4Shell JNDI injection (OOB only)")
    ph.add_argument("--no-headerinject", action="store_true",
                    help="skip header injection (XSS/SQLi/SSTI via headers)")
    ph.add_argument("--no-hpp", action="store_true",
                    help="skip HTTP Parameter Pollution detection")
    ph.add_argument("--no-timesqli", action="store_true",
                    help="skip time-based blind SQLi (auto-skipped when in-band confirms)")

    kn = p.add_argument_group("knobs")
    kn.add_argument("--ports", default=None,
                    help="comma-separated ports (default common set)")
    kn.add_argument("--dns-wordlist", default=None)
    kn.add_argument("--dir-wordlist", default=None)
    kn.add_argument("--max-hosts", type=int, default=25,
                    help="cap hosts for port + vuln scanning")
    kn.add_argument("--nuclei-rate", type=int, default=None,
                    help="nuclei requests/sec (default: derive from --delay; "
                         "raise for faster scans against your own infra)")
    kn.add_argument("--nuclei-timeout", type=int, default=900,
                    help="max seconds for the nuclei phase (default 900)")
    kn.add_argument("--js-max-files", type=int, default=25,
                    help="max JS files to fetch + analyze (default 25)")
    kn.add_argument("--crawl-depth", type=int, default=3,
                    help="recursive crawl max depth (default 3)")
    kn.add_argument("--crawl-pages", type=int, default=150,
                    help="recursive crawl page budget (default 150)")
    kn.add_argument("--browser-pages", type=int, default=20,
                    help="max pages to render in the headless-browser phase (default 20)")
    kn.add_argument("--wayback-limit", type=int, default=5000,
                    help="max Wayback/CDX rows to request (default 5000)")
    kn.add_argument("--max-requests", type=int, default=0,
                    help="global cap on outbound requests (0=unlimited) — safety "
                         "valve for large multi-subdomain runs")
    kn.add_argument("--param-wordlist", default=None,
                    help="custom hidden-parameter wordlist (default: built-in)")
    return p.parse_args(argv)


def build_config(ns: argparse.Namespace) -> Config:
    ports = DEFAULT_PORTS
    if ns.ports:
        ports = [int(x) for x in ns.ports.split(",") if x.strip().isdigit()]
    out = ns.output or f"output/{ns.target.strip().lower()}"
    extras = [h.strip() for h in ns.extra_scope.split(",") if h.strip()]
    return Config(
        target=ns.target, output_dir=out,
        delay=ns.delay, rate_limit=ns.rate_limit, timeout=ns.timeout,
        threads=ns.threads, workers=ns.workers, verify_tls=ns.verify_tls,
        max_requests=ns.max_requests, rotate_ua=not ns.no_rotate_ua,
        extra_in_scope=extras,
        auth_cookie=ns.cookie, auth_bearer=ns.auth_bearer, auth_headers=ns.header,
        do_oob=not ns.no_oob, oob_provider=ns.oob_provider,
        ngrok_domain=ns.ngrok_domain,
        do_subdomains=not ns.no_subdomains, do_dns=not ns.no_dns,
        do_ports=not ns.no_ports, do_probe=not ns.no_probe,
        do_fingerprint=not ns.no_fingerprint, do_endpoints=not ns.no_endpoints,
        do_vuln=not ns.no_vuln, use_nuclei=not ns.no_nuclei,
        nuclei_rate=ns.nuclei_rate, nuclei_timeout=ns.nuclei_timeout,
        use_external=not ns.no_external, dir_brute=not ns.no_dir_brute,
        do_jsintel=not ns.no_jsintel, do_wayback=not ns.no_wayback,
        do_crawl=not ns.no_crawl, use_katana=not ns.no_katana,
        crawl_depth=ns.crawl_depth, crawl_max_pages=ns.crawl_pages,
        do_exposure=not ns.no_exposure, do_oauth=not ns.no_oauth,
        do_browser=not ns.no_browser, browser_max_pages=ns.browser_pages,
        do_takeover=not ns.no_takeover, do_graphql=not ns.no_graphql,
        do_validate=not ns.no_validate, do_cve_intel=not ns.no_cve_intel,
        do_active=not ns.no_active,
        do_exploit=not ns.no_exploit, do_chain=not ns.no_chain,
        do_apispec=not ns.no_apispec, do_parammine=not ns.no_parammine,
        do_sourcemap=not ns.no_sourcemap, do_blindxss=not ns.no_blindxss,
        do_race=not ns.no_race,
        do_protopollution=not ns.no_protopollution,
        do_log4shell=not ns.no_log4shell,
        do_headerinject=not ns.no_headerinject,
        do_hpp=not ns.no_hpp,
        do_timesqli=not ns.no_timesqli,
        js_max_files=ns.js_max_files, wayback_limit=ns.wayback_limit,
        param_wordlist=ns.param_wordlist,
        ports=ports, dns_wordlist=ns.dns_wordlist, dir_wordlist=ns.dir_wordlist,
        max_hosts_deep_scan=ns.max_hosts,
    )


def confirm_authorization(cfg: Config, skip: bool) -> bool:
    print(BANNER)
    print(LEGAL)
    print(f"\n  Target apex : {cfg.target}")
    print(f"  Extra scope : {cfg.extra_in_scope or '(none)'}")
    print(f"  Rate        : >= {cfg.min_interval:.2f}s between requests\n")
    if skip:
        log("warn", "authorization confirmation skipped (--yes)")
        return True
    try:
        ans = input(f"Type the target apex '{cfg.target}' to confirm authorization: ").strip()
    except EOFError:
        return False
    return ans.lower() == cfg.target.lower()


def run(cfg: Config) -> dict:
    tools = detect()
    log("info", "external tools: " +
        ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in tools.items()))

    audit = AuditLog(cfg.audit_file)
    scope = Scope(cfg.target, cfg.extra_in_scope)
    client = Client(cfg, scope, audit)

    started = datetime.now(timezone.utc)
    t0 = time.time()
    recon: dict = {"subdomains": [], "dns_records": {}, "ports": {},
                   "probes": [], "fingerprints": [], "endpoints": [],
                   "jsintel": {}, "wayback": {}, "favicon": [], "chains": [],
                   "crawl": {}, "browser": {}}
    findings: List[Finding] = []
    crawl_forms: List[dict] = []
    warnings: List[str] = []
    triage: dict = {}
    pool = cf.ThreadPoolExecutor(max_workers=cfg.effective_workers)
    log("info", f"parallel workers: {cfg.effective_workers} "
                f"(target HTTP rate still bounded by --delay={cfg.delay}s)")

    # ---- STAGE 0: independent kickoffs (subdomains, dns, wayback overlap) ----
    f_dns = pool.submit(dns_records.gather, cfg.target, audit) if cfg.do_dns else None
    f_wayback = pool.submit(wayback.mine, cfg.target, scope, audit,
                            limit=cfg.wayback_limit) if cfg.do_wayback else None

    # resolve the apex without any :port (resolve_a can't take host:port); a
    # literal IP or an explicitly port-qualified target is always probe-worthy.
    apex_host = cfg.target.split(":", 1)[0]
    if cfg.do_subdomains:
        recon["subdomains"] = subdomains.enumerate_subdomains(cfg, scope, audit)
    else:
        recon["subdomains"] = [{"host": cfg.target,
                                "addresses": dns_records.resolve_a(apex_host),
                                "live": True}]

    live_hosts = [s["host"] for s in recon["subdomains"] if s.get("live")]
    # the explicit target must always be probed — include it if it resolves, is a
    # literal IP, carries an explicit port, or nothing else came back live (so a
    # full scan of an IP/host:port target never silently probes 0 hosts).
    if cfg.target not in live_hosts and (
            dns_records.resolve_a(apex_host) or _looks_like_ip(apex_host)
            or ":" in cfg.target or not live_hosts):
        live_hosts.insert(0, cfg.target)

    deep_hosts = live_hosts[: cfg.max_hosts_deep_scan]
    if len(live_hosts) > len(deep_hosts):
        log("warn", f"capping deep scan to {len(deep_hosts)}/{len(live_hosts)} hosts "
                    f"(raise with --max-hosts)")

    # ---- STAGE 1: ports (nmap) + probe (HTTP) run concurrently ----
    f_ports = pool.submit(portscan.scan, deep_hosts, cfg, audit) if cfg.do_ports else None

    if cfg.do_probe:
        recon["probes"], failed_hosts = prober.probe(client, live_hosts, cfg)
        if failed_hosts:
            w = (f"{len(failed_hosts)} live host(s) failed all HTTP probes at the "
                 f"transport level (network blip / blocked egress?): "
                 f"{', '.join(failed_hosts)}")
            warnings.append(w)
            log("warn", w)
        if live_hosts and not recon["probes"]:
            w = ("DEGRADED RUN: every live host failed HTTP probing — results below "
                 "reflect a probe failure, NOT a clean target. Re-run before trusting.")
            warnings.append(w)
            log("err", w)

    # collect the early concurrent results
    if f_ports is not None:
        recon["ports"] = f_ports.result()
    if f_dns is not None:
        recon["dns_records"] = f_dns.result()

    if cfg.do_fingerprint:
        recon["fingerprints"] = fp.fingerprint(recon["probes"])

    # ---- IN-SCOPE SERVICE DEDUP ---- (defined before favicon needs it)
    # One canonical HTTP service per final (in-scope) base URL. This collapses
    # www<->apex and trailing-slash duplicates, and DROPS hosts whose only
    # response is an off-scope redirect (e.g. mail host -> 3rd-party SSO).
    services = _services(recon["probes"], scope, deep_hosts)
    skipped = _offscope_hosts(recon["probes"], deep_hosts)
    if skipped:
        log("info", f"skipping {len(skipped)} off-scope redirector host(s): "
                    f"{', '.join(skipped)}")
    service_bases = [s["base_url"] for s in services]

    # favicon hash pivot (one per canonical service)
    if cfg.do_fingerprint and services:
        favs = []
        for s in services[:cfg.max_hosts_deep_scan]:
            fh = favicon.favicon_hash(client, s["base_url"])
            if fh:
                fh["base_url"] = s["base_url"]
                favs.append(fh)
        recon["favicon"] = favs

    # ---- STAGE 2: launch nuclei EARLY so it overlaps the HTTP vuln phases ----
    f_nuclei = None
    if cfg.do_vuln and cfg.use_nuclei and service_bases:
        f_nuclei = pool.submit(vnuclei.check, service_bases, cfg, audit)

    # endpoints (HTTP) — one per canonical service
    if cfg.do_endpoints:
        recon["endpoints"] = [endp.discover(client, s["base_url"], cfg) for s in services]

    # OpenAPI/Swagger ingestion — documented endpoints + params -> exploit surface
    spec_urls: List[str] = []
    if cfg.do_apispec and services:
        spec_findings, spec_urls = apispec.discover(client, services, scope, cfg)
        findings += spec_findings

    # JS intel on canonical services
    if cfg.do_jsintel and services:
        js_findings, js_summary = jsintel.analyze(
            client, scope, [s["primary"] for s in services], cfg,
            max_files=cfg.js_max_files)
        findings += js_findings
        recon["jsintel"] = js_summary

    # recursive crawl — the single biggest surface expander. Seeds from service
    # bases + endpoint/robots/sitemap + JS-mined routes; merges everything it
    # finds back into recon["endpoints"] so EVERY later phase (active probing,
    # injection, IDOR, LFI, clairvoyance) automatically chews the wider surface.
    if cfg.do_crawl and services:
        seeds = list(service_bases)
        for ep in recon["endpoints"]:
            b = ep.get("base_url")
            for d in ep.get("discovered", []):
                if isinstance(d, dict) and d.get("url"):
                    seeds.append(d["url"])
            seeds += [loc for loc in ep.get("sitemap", []) if loc]
            for pth in ep.get("robots", []):
                if b and pth.startswith("/"):
                    seeds.append(urljoin(b, pth))
        base0 = service_bases[0]
        for e in (recon.get("jsintel", {}) or {}).get("endpoints", []):
            seeds.append(e if e.startswith("http") else urljoin(base0, e))
        crawl = crawler.crawl(client, scope, seeds, cfg, audit)
        crawl_forms = crawl["forms"]
        _merge_crawl(recon["endpoints"], crawl["urls"], service_bases, scope)
        recon["crawl"] = {"pages_crawled": crawl["pages_crawled"],
                          "urls_found": len(crawl["urls"]),
                          "forms_found": len(crawl["forms"]),
                          "params_found": len(crawl["params"]),
                          "katana_used": crawl["katana_used"]}

    # headless-browser phase — renders the JS the static crawler can't (SPAs hide
    # their routes + XHRs behind render), captures the in-scope endpoints the app
    # actually calls, and execution-confirms DOM-XSS. Merges its surface back in
    # too. Auto-skips when playwright/Chromium is absent.
    if cfg.do_browser and services:
        all_disc = []
        for ep in recon["endpoints"]:
            for d in ep.get("discovered", []):
                if isinstance(d, dict) and d.get("url"):
                    all_disc.append(d["url"])
        bseeds = dedup_keep_order(list(service_bases) + all_disc)
        bparams = [u for u in all_disc if "?" in u]
        bfindings, bsum = browserphase.run(scope, bseeds, bparams, cfg, audit)
        findings += bfindings
        if not bsum.get("skipped"):
            _merge_crawl(recon["endpoints"], bsum.get("urls", []), service_bases, scope)
            crawl_forms = crawl_forms + bsum.get("forms", [])
        recon["browser"] = {k: v for k, v in bsum.items() if k not in ("urls", "forms")}

    # takeover (DNS-bound) can run while endpoints/js HTTP work proceeds — but to
    # keep ordering simple and output readable, run it here on deep hosts.
    if cfg.do_takeover:
        findings += takeover.scan(client, deep_hosts, cfg)

    # ---- vuln (detection only), scoped to in-scope services ----
    if cfg.do_vuln:
        ep_by_base = {e["base_url"]: e for e in recon["endpoints"]}
        for s in services:
            primary, base_url = s["primary"], s["base_url"]
            findings += vheaders.check(primary)
            findings += vcors.check(client, primary)
            findings += vrefl.check(client, primary)
            ep = ep_by_base.get(base_url) or {"discovered": []}
            findings += vmisc.check(client, primary, ep)

        # TLS runs per live deep host (direct socket, no redirect follow) — safe
        # even for off-scope redirector hosts since we connect to the host itself.
        probes_by_host = _group_probes(recon["probes"])
        for host in deep_hosts:
            plist = probes_by_host.get(host)
            if plist:
                findings += vtls.check(client, host, plist, audit)

        for fpr in recon["fingerprints"]:
            findings += vcve.check(fpr)

        if cfg.do_graphql:
            findings += vgraphql.check(client, service_bases)

        # email auth posture (pure DNS, zero target requests)
        findings += vemail.check(cfg.target, recon.get("dns_records", {}))
        # sensitive-data exposure in any in-scope response body
        findings += vdataleak.check(recon["probes"])
        # exposed .git / Spring actuator / dotfile extraction (confirmed, low-FP)
        findings += vexposure.check(client, service_bases, cfg, audit)

    # join nuclei (was running concurrently)
    if f_nuclei is not None:
        findings += f_nuclei.result()

    # wayback result (was running since stage 0)
    if f_wayback is not None:
        _juicy, recon["wayback"] = f_wayback.result()

    pool.shutdown(wait=True)

    # ---- active probing (lead generation) ----
    if cfg.do_active and services:
        findings += run_active(client, scope, services, recon["endpoints"], cfg)
        # WAF/CDN fingerprint (informs evasion-encoded injection fallbacks)
        findings += vwaf.check(client, service_bases)
        # modern targeted checks
        gated = _gated_urls(recon["endpoints"], service_bases)
        findings += vnextjs.check(client, gated, recon["fingerprints"])
        findings += vcache.check(client, service_bases)
        findings += vwcd.check(client, service_bases, recon["endpoints"], cfg, scope, audit)
        findings += vsmuggling.check(client, service_bases, cfg)
        # HTTP Parameter Pollution (active phase — uses param surface)
        if cfg.do_hpp:
            _hpp_surface = {"urls": [d.get("url", "") for ep in recon["endpoints"]
                                      for d in ep.get("discovered", [])
                                      if isinstance(d, dict) and "?" in d.get("url", "")],
                            "forms": []}
            findings += ahpp.exploit(client, _hpp_surface, cfg)

    # ---- exploitation (confirm + PoC) ----
    oob = None
    try:
        if cfg.do_exploit and services:
            if cfg.do_oob:
                oob = OOBClient(provider=cfg.oob_provider,
                                ngrok_domain=cfg.ngrok_domain,
                                out_file=os.path.join(cfg.output_dir,
                                                      "oob_interactions.jsonl"))
                oob.start()
            js_eps = (recon.get("jsintel", {}) or {}).get("endpoints", [])
            findings += run_exploit(client, scope, services, recon["endpoints"],
                                    recon["probes"], js_eps, cfg, oob=oob,
                                    extra_urls=spec_urls, crawl_forms=crawl_forms)
            if oob and oob.enabled:
                recon["oob"] = {"provider": oob.backend.name, "domain": oob.domain,
                                "dns_capable": oob.dns_capable}
    finally:
        if oob:
            oob.stop()

    # ---- exploit chaining (assemble high-impact attack paths) ----
    if cfg.do_chain:
        ctx = _chain_context(recon, findings)
        chains = build_chains(findings, ctx)
        findings += chains
        recon["chains"] = [c.to_dict() for c in chains]

    # ---- CVE -> exploitation intel (pre-exploit research, non-destructive) ----
    if cfg.do_cve_intel:
        findings += cveintel.enrich(findings, audit)

    # ---- validation / false-positive filtering ----
    if cfg.do_validate and findings:
        findings, filtered, triage = validator.validate(client, findings, cfg)
        recon["filtered_findings"] = [f.to_dict() for f in filtered]

    # ---- bounty prioritization ----
    prioritize(findings)
    hunts = top_hunts(findings)

    finished = datetime.now(timezone.utc)
    meta = {
        "tool": "reconscan", "version": __version__,
        "target": cfg.target,
        "started": started.isoformat(), "finished": finished.isoformat(),
        "duration_s": round(time.time() - t0, 1),
        "config": cfg.to_dict(), "tools": tools,
        "warnings": warnings,
        "triage": triage,
    }
    report = reporter.build(meta, recon, findings, audit.count(),
                            hunts=[h.to_dict() for h in hunts])
    paths = reporter.emit(report, cfg.output_dir, cfg.target)
    report["_paths"] = paths
    _print_final(report)
    return report


# --------------------------------------------------------------- helpers
def _host_of(probe: dict) -> str:
    return urlparse(probe.get("url", "")).netloc


def _group_probes(probes: List[dict]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {}
    for p in probes:
        host = urlparse(p["url"]).netloc
        out.setdefault(host, []).append(p)
    return out


def _primary_probe(plist: List[dict]) -> dict:
    https = [p for p in plist if p.get("scheme") == "https"]
    return https[0] if https else plist[0]


def _norm_base(url: str) -> str:
    """Canonical base URL: scheme://netloc + path without trailing slash.
    Collapses `https://h` and `https://h/` to the same key."""
    pr = urlparse(url)
    path = (pr.path or "").rstrip("/")
    return f"{pr.scheme}://{pr.netloc}{path}"


def _services(probes: List[dict], scope, deep_hosts: List[str]) -> List[dict]:
    """One canonical in-scope HTTP service per final base URL.

    - request host must be a deep host,
    - the final hop must be in scope (drops off-scope redirectors),
    - dedupe by canonical final base (collapses www<->apex + trailing slash),
    - prefer the https probe.
    Returns [{host, base_url, primary}].
    """
    deep = set(deep_hosts)
    best: Dict[str, dict] = {}
    for p in probes:
        if _host_of(p) not in deep:
            continue
        if not p.get("final_host_in_scope", True):
            continue
        final = p.get("final_url") or p.get("url")
        canon = _norm_base(final)
        cur = best.get(canon)
        if cur is None or (p.get("scheme") == "https" and cur.get("scheme") != "https"):
            best[canon] = p
    out = []
    for canon, p in best.items():
        out.append({"host": urlparse(canon).netloc, "base_url": canon, "primary": p})
    return out


def _looks_like_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _merge_crawl(endpoints: List[dict], urls: List[str],
                 service_bases: List[str], scope) -> None:
    """Fold crawler-discovered URLs into the endpoint 'discovered' lists so every
    downstream consumer (active probing, build_surface, IDOR, etc.) sees them
    without any further plumbing. Grouped by host; deduped against what's there."""
    if not endpoints:
        return
    by_netloc: Dict[str, dict] = {}
    for ep in endpoints:
        by_netloc.setdefault(urlparse(ep.get("base_url", "")).netloc, ep)
    existing: set = set()
    pvar: Dict[str, int] = {}
    for ep in endpoints:
        for d in ep.get("discovered", []):
            if isinstance(d, dict) and d.get("url"):
                existing.add(d["url"])
                if "?" in d["url"]:
                    pr = urlparse(d["url"])
                    pvar[f"{pr.netloc}{pr.path}"] = pvar.get(f"{pr.netloc}{pr.path}", 0) + 1
    default_ep = endpoints[0]
    for u in urls:
        if u in existing or not scope.url_in_scope(u) or is_catch_all_artifact(u):
            continue
        # cap query-variants per path (cache-buster / soft-404 explosion guard)
        if "?" in u:
            pr = urlparse(u)
            pk = f"{pr.netloc}{pr.path}"
            if pvar.get(pk, 0) >= 3:
                continue
            pvar[pk] = pvar.get(pk, 0) + 1
        ep = by_netloc.get(urlparse(u).netloc, default_ep)
        ep.setdefault("discovered", []).append(
            {"url": u, "status": None, "source": "crawl"})
        existing.add(u)


def _chain_context(recon: dict, findings: List[Finding]) -> dict:
    """Signals the chaining engine needs: are login/OAuth/cookies/admin present?"""
    blob_parts = []
    for ep in recon.get("endpoints", []):
        blob_parts += [d.get("url", "") for d in ep.get("discovered", []) if isinstance(d, dict)]
        blob_parts += ep.get("sitemap", []) + ep.get("robots", [])
    blob_parts += (recon.get("jsintel", {}) or {}).get("endpoints", [])
    blob = " ".join(blob_parts).lower()

    has_cookies = False
    has_login = False
    for p in recon.get("probes", []):
        if "set-cookie" in (p.get("headers") or {}):
            has_cookies = True
        body = (p.get("_body", "") or "").lower()
        if 'type="password"' in body or "type=password" in body:
            has_login = True
    if any(k in blob for k in ("login", "signin", "sign-in", "auth")):
        has_login = True
    return {
        "has_cookies": has_cookies,
        "has_login": has_login,
        "has_oauth": any(k in blob for k in ("oauth", "/authorize", "openid",
                                             "sso", "saml", "redirect_uri")),
        "has_admin": "admin" in blob or bool(_gated_urls(recon.get("endpoints", []), [])),
    }


_GATED_CODES = {301, 302, 303, 307, 308, 401, 403}


def _gated_urls(endpoints: List[dict], base_urls: List[str]) -> List[str]:
    """URLs that look access-gated (auth redirect / 401 / 403) — candidates for
    the Next.js middleware-bypass + 403-bypass checks."""
    out = []
    for ep in endpoints:
        for d in ep.get("discovered", []):
            if isinstance(d, dict) and d.get("status") in _GATED_CODES:
                out.append(d["url"])
    return dedup_keep_order(out)[:10]


def _offscope_hosts(probes: List[dict], deep_hosts: List[str]) -> List[str]:
    deep = set(deep_hosts)
    bad = []
    for host in deep:
        plist = [p for p in probes if _host_of(p) == host]
        if plist and all(not p.get("final_host_in_scope", True) for p in plist):
            bad.append(host)
    return sorted(bad)


def _print_final(report: dict) -> None:
    s = report["summary"]
    bs = s["by_severity"]
    log("step", "SCAN COMPLETE")
    log("ok", f"subdomains: {s['subdomains_live']} live / {s['subdomains_total']} total")
    log("ok", f"http services: {s['http_services']}")
    log("ok", f"requests logged: {s['audit_requests_logged']}")
    log("ok", f"findings: {s['total_findings']} "
             f"(crit {bs['critical']}, high {bs['high']}, med {bs['medium']}, "
             f"low {bs['low']}, info {bs['info']})")
    if s.get("confirmed_exploits") or s.get("chains"):
        log("vuln", f"CONFIRMED EXPLOITS: {s.get('confirmed_exploits',0)} · "
                    f"ATTACK CHAINS: {s.get('chains',0)}")
    tri = s.get("triage") or {}
    if tri:
        log("ok", f"triage: {tri.get('reconfirmed',0)} re-confirmed, "
                  f"{tri.get('filtered_false_positive',0)} FP filtered, "
                  f"{tri.get('duplicates_removed',0)} dupes removed")
    hunts = report.get("top_hunts", [])
    if hunts:
        log("step", "TOP HUNTS (ranked by bounty potential)")
        for h in hunts:
            log("vuln", f"[{h['severity']}] (score {h.get('priority',0)}) "
                        f"{h['title']} @ {h['target']}")
    for w in report.get("meta", {}).get("warnings", []):
        log("warn", w)
    paths = report.get("_paths", {})
    if paths.get("summary"):
        log("step", f"REPORT (md):   {paths['summary']}")
    if paths.get("html"):
        log("step", f"REPORT (html): {paths['html']}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ns = parse_args(argv)
    set_verbosity(-1 if ns.quiet else (1 if ns.verbose else 0))
    cfg = build_config(ns)
    if not confirm_authorization(cfg, ns.yes):
        log("err", "authorization not confirmed — aborting.")
        return 2
    try:
        run(cfg)
    except KeyboardInterrupt:
        log("warn", "interrupted by user")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

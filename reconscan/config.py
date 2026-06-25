"""Central configuration for a scan run."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional


DEFAULT_UA = "reconscan/0.1 (+authorized-security-testing)"

# Conservative defaults. Override on the CLI.
DEFAULT_DELAY = 1.0        # seconds between requests (per worker pool, enforced globally)
DEFAULT_TIMEOUT = 10.0     # per-request timeout
DEFAULT_THREADS = 5        # concurrency cap (global rate limiter still bounds throughput)
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                 3000, 3306, 5432, 6379, 8000, 8080, 8443, 8888, 9200]


@dataclass
class Config:
    target: str                                   # apex domain, e.g. example.com
    output_dir: str = "output"
    audit_file: str = ""                          # filled in __post_init__

    # --- politeness / safety ---
    delay: float = DEFAULT_DELAY
    rate_limit: Optional[float] = None            # requests/sec; if set, interval=max(delay,1/rl)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    workers: int = 0                               # 0 = auto-detect from CPU count
    max_requests: int = 0                          # global request cap (0=unlimited)
    user_agent: str = DEFAULT_UA
    rotate_ua: bool = True                          # rotate a realistic UA per request
    verify_tls: bool = False                       # don't choke on self-signed during recon
    max_retries: int = 2

    # --- scope guard (non-negotiable) ---
    # Only the apex and its subdomains are ever contacted. Extra allowed hosts
    # can be added explicitly (e.g. a known asset on another domain you own).
    extra_in_scope: List[str] = field(default_factory=list)

    # --- authenticated scanning (most real bugs sit BEHIND login) ---
    # Provide a session and every phase runs authenticated automatically.
    auth_cookie: str = ""                          # "name=val; n2=v2"
    auth_bearer: str = ""                          # Authorization: Bearer <token>
    auth_headers: List[str] = field(default_factory=list)  # raw "K: V" strings

    # --- out-of-band (OOB) interaction server — confirms BLIND bugs ---
    do_oob: bool = True
    oob_provider: str = "auto"                     # auto | interactsh | ngrok
    ngrok_domain: str = ""                          # reserved ngrok domain for the fallback
    do_blindxss: bool = True                        # plant blind/stored XSS callbacks

    # --- phase toggles ---
    do_subdomains: bool = True
    do_dns: bool = True
    do_ports: bool = True
    do_probe: bool = True
    do_fingerprint: bool = True
    do_endpoints: bool = True
    do_vuln: bool = True
    use_nuclei: bool = True                        # only if nuclei binary present
    nuclei_rate: Optional[int] = None              # nuclei req/sec; None=derive from delay
    nuclei_timeout: int = 900                      # max seconds for the nuclei phase
    use_external: bool = True                      # subfinder/httpx/nmap if present
    # --- elite phases ---
    do_jsintel: bool = True                        # JS endpoint + secret mining
    do_crawl: bool = True                          # recursive in-scope crawl (surface expansion)
    crawl_depth: int = 3                           # max crawl recursion depth
    crawl_max_pages: int = 150                     # global page budget for the crawl
    use_katana: bool = True                        # use katana binary as a crawl accelerator if present
    do_browser: bool = True                        # headless-browser SPA render + DOM-XSS (auto-skips if no playwright)
    browser_max_pages: int = 20                    # max pages to render in the browser phase
    do_exposure: bool = True                       # .git / actuator / .env exposure extraction
    do_oauth: bool = True                          # OAuth/OIDC redirect_uri + flow weaknesses
    do_wayback: bool = True                        # historical URL mining (CDX)
    do_takeover: bool = True                       # subdomain takeover checks
    do_graphql: bool = True                        # GraphQL introspection check
    do_validate: bool = True                       # FP-filtering / re-confirm pass
    do_cve_intel: bool = True                      # CVE -> exploitation intel
    do_active: bool = True                         # active probing (bypass/injection leads)
    do_exploit: bool = True                        # exploitation (confirm + PoC)
    do_chain: bool = True                          # exploit-chaining engine
    do_apispec: bool = True                        # OpenAPI/Swagger ingestion -> surface
    do_parammine: bool = True                      # hidden-parameter discovery (Arjun-style)
    do_sourcemap: bool = True                      # JS sourcemap recovery + DOM-sink mining
    js_max_files: int = 25                         # cap JS files fetched
    param_wordlist: Optional[str] = None           # file; falls back to built-in PARAM_WORDS
    wayback_limit: int = 5000                      # cap CDX rows requested
    # --- new exploit modules ---
    do_race: bool = True                           # race-condition detection
    do_protopollution: bool = True                 # prototype pollution detection
    do_log4shell: bool = True                      # Log4Shell JNDI injection (OOB only)
    do_headerinject: bool = True                   # header injection (XSS/SQLi/SSTI)
    do_hpp: bool = True                            # HTTP Parameter Pollution
    do_timesqli: bool = True                       # time-based blind SQLi (slow; auto-skipped when in-band confirms)
    validate_secrets: bool = False                 # OPT-IN: replay mined secrets read-only against issuer APIs (3rd-party)

    # --- knobs ---
    ports: List[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    dns_wordlist: Optional[str] = None             # file; falls back to built-in
    dir_wordlist: Optional[str] = None             # file; falls back to built-in
    dir_brute: bool = True
    max_subdomain_resolve: int = 2000              # safety cap
    max_hosts_deep_scan: int = 25                  # cap deep (vuln) scanning breadth

    def __post_init__(self) -> None:
        self.target = self.target.strip().lower().rstrip(".")
        if self.target.startswith(("http://", "https://")):
            self.target = self.target.split("://", 1)[1].split("/", 1)[0]
        os.makedirs(self.output_dir, exist_ok=True)
        if not self.audit_file:
            self.audit_file = os.path.join(self.output_dir, "audit.jsonl")

    @property
    def effective_workers(self) -> int:
        """Parallelism for independent phases. Auto-scales to the machine's CPU
        count when workers==0. Note: target HTTP throughput is still bounded by
        the global rate limiter (politeness); this overlaps independent work
        (nuclei/nmap/wayback/DNS) for wall-clock speedup."""
        if self.workers and self.workers > 0:
            return self.workers
        cpu = os.cpu_count() or 4
        return max(4, min(16, cpu * 2))

    @property
    def min_interval(self) -> float:
        """Minimum seconds between any two outbound HTTP requests (global)."""
        rl_interval = (1.0 / self.rate_limit) if self.rate_limit else 0.0
        return max(self.delay, rl_interval)

    def to_dict(self) -> dict:
        return asdict(self)

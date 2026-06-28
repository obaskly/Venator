# Venator

A **modular CLI** for authorized recon and **autonomous exploitation**, built to compress recon → triage → exploit → confirm into one audit-logged run. It does not just flag bugs — it confirms them with a working PoC, capturing a minimal proof rather than dumping data so the output is report-ready. Items it cannot auto-confirm are reported as leads that state exactly what is left to check.

> ⚠️ Use **only** against assets you own or have **explicit written permission** to test. Gate offensive phases with `--no-exploit` / `--no-chain` / `--no-active` where program rules require passive testing.

---

<details>
<summary><strong>🔓 Exploitation &amp; Chaining</strong></summary>
<br>

Venator **confirms** vulnerabilities by demonstrating impact, then **chains** them into submittable, high-payout attack paths:

- **Exploitation phase** — auto-detects HTML forms and JSON APIs (no per-site config): SQLi/NoSQLi auth bypass, mass-assignment privilege escalation, reflected XSS execution, OS command injection (`id` output), LFI/path traversal (read-only, hard-signature confirmed), WAF-aware retries (comment-split, base64 wraps, keyword case-mix), JWT weaknesses (alg:none, weak-secret crack), IDOR probing, sensitive-data exposure (Luhn cards, private keys). Each finding is marked `EXPLOITED` with a copy-paste `curl` PoC.
- **File-upload → RCE / stored XSS** — auto-detects multipart upload forms + endpoints, runs a bypass matrix (extension tricks `.php`/`.phtml`/`.phar`/double-ext/trailing-dot/case/null-byte, content-type spoof, `GIF89a` magic-byte prefix, SVG/HTML), then **confirms by fetching the file back**: an executed arithmetic marker (raw `<?php` absent) proves RCE; a surviving script with a renderable content-type proves stored XSS. Learns the storage location from one benign probe first to stay inside budget.
- **LLM / AI prompt injection (OWASP LLM01)** — finds chat/assistant/RAG endpoints and confirms instruction override with an oracle a plain echo can't fake: it sends a *lowercase* canary and tells the model to reply UPPERCASED — only a model that follows the injected instruction emits the uppercased token. Follows up to surface a **system-prompt / instruction leak** (LLM07).
- **Client-side path traversal (CSPT / CSPT2CSRF)** — in the headless browser, injects a `../`-prefixed canary into a query parameter and confirms (execution-based) when the page's own JS concatenates it into the **path** of a same-origin request it fires — the on-site request-forgery primitive that defeats SameSite cookies and CSRF tokens.
- **Deep class coverage** — broken auth (default creds + user enum), GraphQL (introspection + clairvoyance schema recovery + alias/array batching + resolver injection → RCE/SQLi), stored XSS, CSRF, SSTI→RCE (8 template engines), XXE (in-band file read), HTTP request smuggling (CL.TE/TE.CL), WebSocket CSWSH.
- **CRLF injection** — confirms only when the uniquely-named injected header appears as a real parsed response header. Effectively zero false positives.
- **Web cache deception** — proves a route is private, requests it as `…/x.css`, then re-fetches anonymously to confirm a cache leak.
- **Web cache poisoning** — injects unkeyed headers (`X-Forwarded-Host`, `X-Host`, `Forwarded`, `X-Original-URL`…) carrying a canary, then **confirms** by re-requesting the same throwaway `?cb=` key *without* the header: if the canary persists it was cached and the header is unkeyed (proven poisoning, not a guess). Only ever touches its own cache-buster key — never a shared production entry.
- **Blind SQLi** — time-based (MySQL/Postgres/MSSQL/Oracle/SQLite, delay must scale) and OOB-based (`xp_dirtree`, `UTL_HTTP`, `LOAD_FILE`).
- **JWT forge + replay** — confirms signature-not-verified, RS256→HS256 algorithm confusion, alg:none, embedded-`jwk` self-sign (CVE-2018-0114), `kid` path-traversal, jku/x5u header injection. Negative-control separates true findings.
- **API authorization + SSRF** — BOLA/IDOR (confirms when other users' PII returns per id), JSON-body SSRF (learns body from validation errors, confirms in-band or via OOB) against AWS / GCP / Azure IMDS / Alibaba / DigitalOcean metadata (with decimal-IP filter-bypass).
- **BFLA — broken function-level auth (OWASP API5)** — privilege differential across outsider (bogus token) / actor / anonymous identities: confirms a privileged function reachable unauthenticated, or a low-privilege token reaching a strongly admin-named function an outsider is denied. GET-only, guarded by catch-all / homepage / login-page checks.
- **Race / TOCTOU** — fires a synchronized concurrent burst (thread-barrier so the requests actually land together) at state-change endpoints; confirms only when multiple requests win past a guard that the app's own conflict response proves should allow one (negative-controlled against static page text).
- **Prototype pollution** — injects `__proto__` (JSON body + query string) and confirms via a *clean* follow-up request that leaks the injected junk property — process-wide `Object.prototype` pollution, not mere reflection (near-zero FP).
- **HTTP Parameter Pollution** — duplicate-param last/first-value differential (WAF-bypass signal) plus duplicate-only SQL-error / 5xx detection. Only fires when the two single-value baselines genuinely differ.
- **Header injection** — XSS / SQLi / SSTI through request headers (User-Agent, Referer, X-Forwarded-For…), reflection-gated so template/script payloads only hit headers the app actually echoes.
- **Log4Shell (CVE-2021-44228)** — JNDI injection into 13 commonly-logged headers + URL params with WAF-evasion variants; OOB-only confirmation (zero in-band false positives).
- **OOB (blind bug confirmation)** — spins up an interactsh collaborator (ngrok fallback), confirms blind SSRF, blind RCE, blind XXE, blind/stored XSS.
- **Authenticated scanning** — `--cookie`, `--auth-bearer`, `--header` make every phase run as a logged-in user. Logout / sign-out links are auto-excluded from the crawler, browser, and attack surface so the session can't be dropped mid-scan.
- **Surface expansion** — recursive in-scope crawler (BFS + katana), hidden-parameter discovery, OpenAPI/Swagger ingestion, JS source-map recovery, DOM-XSS source→sink leads.
- **Headless browser** — Playwright renders SPAs, captures XHR/fetch endpoints, and confirms DOM-XSS execution (payload must actually fire — zero FP). Also audits `window.postMessage` listeners for a missing origin check feeding a dangerous sink (innerHTML/eval/location), and confirms **client-side prototype pollution** by navigating `?__proto__[x]=y` shapes and reading `Object.prototype` back live in the page. Auto-skips if Playwright isn't installed.
- **Exposure extraction** — `.git/` (validates ref shape, extracts remote URL), `.env` (reports key names, never values), Spring Boot actuator endpoints, `.svn`, Apache `/server-status`.
- **Live secret validation** *(opt-in, `--validate-secrets`)* — replays a mined credential read-only against the API that issued it (GitHub `/user`, Slack `auth.test`, Stripe `/v1/balance`, SendGrid, Mailgun, GitLab, Square, Heroku) and reports which secrets are **actually live** (and the principal they authenticate as) vs. revoked — turning a *"possible secret"* into a confirmed critical. Contacts only allowlisted issuer hosts, never the target, with a fresh connection so your session is never leaked; raw secrets stay out of the report.
- **OAuth / OIDC depth** — OIDC discovery, implicit grant detection, redirect_uri validation weaknesses (error-differential oracle, pre-auth), missing `state` (CSRF).
- **Many bypasses** — 403/401 engine: 51 path mutations × 29 header spoofs × 9 verbs + method-override. Every injection class carries a WAF-evasion payload set (21 SQL, 17 XSS, 32 cmd, multi-engine SSTI).
- **Chaining engine** — SQLi bypass→ATO, XSS→session theft→ATO, SSRF→cloud metadata→IAM creds, open-redirect→OAuth token theft, LFI→secret→escalation, JWT-forge→admin, mass-assign→admin, cache+XSS→mass-ATO, prototype-pollution→RCE, race→business-logic abuse, Log4Shell→full compromise, HPP→WAF bypass, CORS+XSS→exfil, **CSPT→CSRF (CSPT2CSRF), file-upload→RCE→compromise, LLM-injection→excessive-agency→data exfil, public-bucket→secret→cloud-pivot**, and more. Chains score highest in the report.

</details>

---

<details>
<summary><strong>🧠 Why It's Different</strong></summary>
<br>

Most recon scripts dump a flat list. Venator adds the parts that actually win bounties:

- **JS intelligence** — mines JS bundles for hidden API routes and leaked secrets (AWS, Google, Stripe, GitHub, Slack, JWT, private keys…).
- **Wayback / CDX mining** — keyless historical URL discovery; flags forgotten endpoints (`.env`, `.sql`, `/admin`, `?id=`).
- **Cloud bucket enumeration** — derives candidate bucket/account names from the target (`acme-prod`, `acme-backups`, `acme-assets`…) and probes **S3 / GCS / Azure Blob** for public listings (confirmed) or existing-but-private buckets (recon lead). Credential-isolated: a fresh connection to allowlisted cloud hosts only, read-only listings, never the target's session.
- **Subdomain takeover** — dangling-CNAME detection against 17 service fingerprints (S3, GitHub Pages, Heroku, Fastly, Netlify…).
- **Subdomain permutations** — altdns-style mutation engine derives new candidates from already-known subs (tier/service prefixes + numeric increments), resolves them, and wildcard-filters the hits.
- **Deep DNS** — attempts an AXFR zone transfer against every authoritative name server (a single misconfig that dumps the whole zone) and enumerates common SRV service records; any host either discloses is folded straight back into the probe/vuln surface.
- **Broken-link hijacking** — extracts external assets referenced by in-scope pages and flags any whose registrable domain is **unregistered** (NXDOMAIN → claimable for stored-XSS / phishing / supply-chain). DNS-only: it never sends HTTP off-scope and never registers anything.
- **Parameter attack-surface map (gf-style)** — classifies every discovered URL parameter by the bug class its name historically correlates with (SQLi/SSRF/LFI/redirect/SSTI/IDOR/XSS), surfaces interesting files (`.env`/`.bak`/`.git`/`openapi.json`…), and **boosts the hunt ranking** of findings that sit on a high-value parameter. Issues no requests — pure classification of existing surface.
- **GraphQL introspection** — locates GraphQL endpoints and checks if the schema is exposed.
- **CVE → exploitation intel** — enriches detected CVEs with nuclei metadata (CVSS, PoC links) and optional `searchsploit` ExploitDB matches.
- **Validation pass** — re-confirms findings, detects soft-404s (the #1 false-positive source), and de-duplicates.
- **Catch-all / SPA-aware** — drops soft-404 artifacts, collapses cache-buster URL explosions, excludes transport endpoints. Reaches blank-value params and param-less endpoints SPAs only call at user-action time.
- **Bounty prioritization** — every finding is scored (severity + exploitability + asset value + confidence); report leads with a ranked "Hunt these first" list.
- **Active probing (lead generation)** — 403/401 bypass matrix, open redirect, and error/signature-based injection leads, each auto-confirmed by the exploitation phase that follows.
- **Modern CVE/technique checks** — Next.js middleware/App-Router auth bypasses (CVE-2025-29927 `x-middleware-subrequest`, **CVE-2026-44575/44574** `.rsc`/segment-prefetch + `_rsc` query route confusion, plus the **May-2026 proxy/middleware authz batch** — i18n default-locale prefix + path-matcher confusion, each confirmed by serving protected content unauthenticated), web cache poisoning + host-header injection, email spoofing posture (SPF/DMARC). The React Server Components deserialization RCE (CVE-2025-55182, CVSS 10) + RSC DoS chain are covered by the full-library nuclei phase and the CVE-intel pass (version-bound, unsafe to actively confirm).
- **CORS depth** — beyond arbitrary-origin/`null` reflection: subdomain-trust reflection and prefix-match (`trusted.com.attacker.com`) bypasses, each with a unique attacker canary and credential-aware severity.
- **Wildcard-DNS-aware enum** — detects wildcard records and drops ghost subdomains.
- **Favicon mmh3 hash** — Shodan/FOFA pivot to find sibling hosts no DNS brute will surface.
- **Random User-Agent rotation** — realistic browser UAs rotated per request.

</details>

---

<details>
<summary><strong>🛡️ Safety Model</strong></summary>
<br>

Enforced in code, not by convention:

- **Scope guard** — only the target apex, its subdomains, and `--extra-scope` hosts are ever contacted. Out-of-scope URLs raise `ScopeError`, are logged as `BLOCKED_OUT_OF_SCOPE`, and dropped.
- **Global rate limiter** — one thread-safe limiter spaces all outbound requests by `--delay` (or `1/--rate-limit`). More threads ≠ more req/sec.
- **Adaptive back-off** — when the target answers `429`/`503` (honouring `Retry-After`), the spacing widens automatically and eases back after a clean streak. It only ever *slows down* — never below your configured floor — so it can't make a scan louder than you asked. Disable with `--no-adaptive-rate`.
- **Audit log** — every request (method, URL, timestamp, phase, status, tool) appended to `output/<target>/audit.jsonl`.
- **Proof-over-damage** — confirms with minimal benign indicators, not destruction: benign canary tokens for reflection, read-only GraphQL introspection and file/secret reads, junk (non-security) property names for prototype pollution. POST is used only where a bug class requires it (auth bypass, mass-assignment, prototype pollution, race) and the race probe sends one small bounded concurrent burst — no fuzzing, no credential brute, no DoS-style volume.
- **Degraded-run detection** — if every live host fails HTTP probing, the report is flagged `DEGRADED RUN` instead of silently appearing "clean".

</details>

---

<details>
<summary><strong>⚙️ Setup</strong></summary>
<br>

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Requirements:** Python 3.10+. Pure-Python fallbacks mean it runs with zero external binaries.

**Optional binaries** (improve speed/depth if on `PATH`): `subfinder`, `httpx`, `nuclei`, `nmap`, `masscan`, `openssl`, `dig`, `katana`, `searchsploit`. No API key required.

**Headless browser (optional):** `pip install playwright` + Chromium — activates the SPA render + DOM-XSS phase; auto-skips if not installed. Disable with `--no-browser`.

**nuclei** runs the **full template library** (every tag + severity) with the interactsh OOB collaborator on, so blind bugs self-confirm via callback. Only `dos` templates are excluded by default (they impair the target instead of proving a bug) — add `--nuclei-dos` to include them.

</details>

---

<details>
<summary><strong>🚀 Usage</strong></summary>
<br>

```bash
python3 venator.py <apex-domain> [options]
```

On start, it prints the legal banner and asks you to **type the apex domain** to confirm authorization. Skip with `--yes` in automation you control.

**Quick examples:**

```bash
# Full scan (1 req/sec)
python3 venator.py example.com

# Faster, custom output dir
python3 venator.py example.com --yes --delay 0.3 -o output/example

# Fast triage (skip slow phases)
python3 venator.py example.com --yes --no-subdomains --no-ports --no-nuclei

# Deep recon only (no vuln phase)
python3 venator.py example.com --no-vuln

# JS-secret focus
python3 venator.py example.com --js-max-files 60 --no-dir-brute

# Full deep run with nuclei
python3 venator.py example.com --yes --delay 0.2 --nuclei-rate 40 --nuclei-timeout 600 --max-hosts 40
```

</details>

---

<details>
<summary><strong>🚩 Flags Reference</strong></summary>
<br>

**Politeness / safety**
| Flag | Default | Meaning |
|------|---------|---------|
| `--delay <s>` | `1.0` | Seconds between every request (global). |
| `--rate-limit <n>` | — | Max req/sec (stricter of this vs `--delay` wins). |
| `--timeout <s>` | `10.0` | Per-request timeout. |
| `--threads <n>` | `5` | Per-phase HTTP concurrency cap. |
| `--workers <n>` | `0` (auto) | Parallel phase workers; `0` auto-scales to CPU count. |
| `--verify-tls` | off | Verify TLS certificates. |
| `--no-rotate-ua` | off | Disable random User-Agent rotation. |
| `-y, --yes` | off | Skip the authorization confirmation prompt. |
| `--extra-scope <h,h>` | — | Extra in-scope hosts you own (comma-separated). |
| `-q, --quiet` | off | Summaries only — best for many subdomains. |
| `-v, --verbose` | off | Per-request detail + blocked off-scope hosts. |

**Authenticated scanning**
| Flag | Default | Meaning |
|------|---------|---------|
| `--cookie "<c>"` | — | Session cookie(s), e.g. `"session=abc; csrf=xyz"`. |
| `--auth-bearer <tok>` | — | Adds `Authorization: Bearer <tok>` to every request. |
| `--header "K: V"` | — | Extra header on every request (repeatable). |

**Out-of-band (OOB)**
| Flag | Default | Meaning |
|------|---------|---------|
| `--no-oob` | off | Disable OOB collaborator (blind SSRF/RCE/XXE/XSS off). |
| `--oob-provider <p>` | `auto` | `auto` (interactsh→ngrok), `interactsh`, or `ngrok`. |
| `--ngrok-domain <d>` | — | Reserved ngrok domain for the OOB fallback. |

**Phase toggles**

`--no-subdomains` `--no-dns` `--no-ports` `--no-probe` `--no-fingerprint` `--no-endpoints` `--no-vuln` `--no-nuclei` `--no-external` `--no-dir-brute` `--no-jsintel` `--no-wayback` `--no-takeover` `--no-graphql` `--no-validate` `--no-cve-intel` `--no-active` `--no-exploit` `--no-chain` `--no-apispec` `--no-parammine` `--no-sourcemap` `--no-blindxss` `--no-subperms` `--no-urlclass` `--no-brokenlinks` `--no-adaptive-rate` `--no-fileupload` `--no-llminject` `--no-cspt` `--no-cloudassets`

**Knobs**
| Flag | Default | Meaning |
|------|---------|---------|
| `--ports <list>` | common set | Comma-separated ports to scan. |
| `--dns-wordlist <file>` | built-in | Subdomain brute wordlist. |
| `--dir-wordlist <file>` | built-in | Directory brute wordlist. |
| `--max-hosts <n>` | `25` | Cap hosts for port + vuln scanning. |
| `--nuclei-rate <n>` | derived | nuclei requests/sec. |
| `--nuclei-timeout <s>` | `900` | Max seconds for the nuclei phase. |
| `--js-max-files <n>` | `25` | Max JS files to fetch + analyze. |
| `--wayback-limit <n>` | `5000` | Max Wayback/CDX rows to request. |

</details>

---

<details>
<summary><strong>⚡ Performance &amp; Pipeline</strong></summary>
<br>

The scan auto-detects CPU count and runs independent phases concurrently: subdomain enum ∥ DNS ∥ Wayback at start; nmap port scan ∥ HTTP probing; nuclei overlaps the Python vuln checks. Tune with `--workers` (`0` = auto).

**Phase order:**
```
subdomains (+ altdns permutations) → dns (+ AXFR / SRV) → ports → probe
  → fingerprint → endpoints
  → JS intel → recursive crawl (+katana) → headless browser (SPA + DOM-XSS + CSPT)
  → wayback → takeover → broken-link hijack → cloud-bucket enum → favicon hash
  → vuln (headers, tls, cors [deep], reflection, misconfig, graphql, CVE, email,
          exposure: .git / actuator / .env, nuclei)
  → active probing (403/401 bypass, open-redirect, CRLF, injection leads,
                    OAuth, Next.js CVE-2025-29927 + CVE-2026-44575 RSC + 2026 proxy-authz
                    bypass, cache poisoning)
  → exploitation (SQLi auth-bypass, XSS, command injection, file-upload→RCE,
                  LLM prompt injection — PoC)
  → chaining → CVE intel → validation → parameter attack-surface map
  → bounty prioritization → report
```

</details>

---

<details>
<summary><strong>📁 Output</strong></summary>
<br>

```
output/<target>/
├── audit.jsonl       # every request: method, url, timestamp, status, phase, tool
└── report.json       # full machine-readable results

reports/<root>/
├── scan_report.md    # clean text for piping into an LLM
└── scan_report.html  # self-contained dark dashboard for humans
```

Both reports lead with run warnings, the ranked hunt list, and findings (priority score + validation status). The `.html` dashboard includes severity bars, filterable finding cards, recon tables, and favicon Shodan pivots — no external assets, just open in a browser.

</details>

---

<details>
<summary><strong>⚖️ Responsible Use</strong></summary>
<br>

- Only scan assets you **own** or have **explicit written authorization** to test. Stay inside program scope.
- Keep `audit.jsonl` — it's your evidence of what was done, when, and against what.
- `confirmed`/EXPLOITED findings are auto-verified and carry a PoC; leads are clearly marked with what is left to check. Always follow the program's disclosure rules. For subdomain takeover, do **not** claim the resource — document and report it.
- A leaked-secret match is "possible" until verified. **Do not use** a found credential; report it for rotation.
- The **active phase generates leads, not exploits**. Never escalate to `UNION`/`OR 1=1`/time-based/RCE payloads on live data. Disable with `--no-active` where program rules require passive-only testing.
- Unauthorized scanning may be illegal in your jurisdiction. You are responsible for how you use this tool.

</details>

# Venator

An **elite, modular CLI** for authorized recon and non-destructive vulnerability detection — built to compress recon → triage → "what do I test first" into one rate-limited, audit-logged run.

> ⚠️ Use **only** against assets you own or have **explicit written permission** to test. Gate offensive phases with `--no-exploit` / `--no-chain` / `--no-active` where program rules require passive testing.

---

<details>
<summary><strong>🔓 Exploitation &amp; Chaining</strong></summary>
<br>

Venator **confirms** vulnerabilities by demonstrating impact, then **chains** them into submittable, high-payout attack paths:

- **Exploitation phase** — auto-detects HTML forms and JSON APIs (no per-site config): SQLi/NoSQLi auth bypass, mass-assignment privilege escalation, reflected XSS execution, OS command injection (`id` output), LFI/path traversal (read-only, hard-signature confirmed), WAF-aware retries (comment-split, base64 wraps, keyword case-mix), JWT weaknesses (alg:none, weak-secret crack), IDOR probing, sensitive-data exposure (Luhn cards, private keys). Each finding is marked `EXPLOITED` with a copy-paste `curl` PoC.
- **Deep class coverage** — broken auth (default creds + user enum), GraphQL (introspection + clairvoyance schema recovery + alias/array batching + resolver injection → RCE/SQLi), stored XSS, CSRF, SSTI→RCE (8 template engines), XXE (in-band file read), HTTP request smuggling (CL.TE/TE.CL), WebSocket CSWSH.
- **CRLF injection** — confirms only when the uniquely-named injected header appears as a real parsed response header. Effectively zero false positives.
- **Web cache deception** — proves a route is private, requests it as `…/x.css`, then re-fetches anonymously to confirm a cache leak.
- **Blind SQLi** — time-based (MySQL/Postgres/MSSQL/Oracle/SQLite, delay must scale) and OOB-based (`xp_dirtree`, `UTL_HTTP`, `LOAD_FILE`).
- **JWT forge + replay** — confirms signature-not-verified, RS256→HS256 algorithm confusion, alg:none, embedded-`jwk` self-sign (CVE-2018-0114), `kid` path-traversal, jku/x5u header injection. Negative-control separates true findings.
- **API authorization + SSRF** — BOLA/IDOR (confirms when other users' PII returns per id), JSON-body SSRF (learns body from validation errors, confirms in-band or via OOB).
- **OOB (blind bug confirmation)** — spins up an interactsh collaborator (ngrok fallback), confirms blind SSRF, blind RCE, blind XXE, blind/stored XSS.
- **Authenticated scanning** — `--cookie`, `--auth-bearer`, `--header` make every phase run as a logged-in user.
- **Surface expansion** — recursive in-scope crawler (BFS + katana), hidden-parameter discovery, OpenAPI/Swagger ingestion, JS source-map recovery, DOM-XSS source→sink leads.
- **Headless browser** — Playwright renders SPAs, captures XHR/fetch endpoints, and confirms DOM-XSS execution (payload must actually fire — zero FP). Auto-skips if Playwright isn't installed.
- **Exposure extraction** — `.git/` (validates ref shape, extracts remote URL), `.env` (reports key names, never values), Spring Boot actuator endpoints, `.svn`, Apache `/server-status`.
- **OAuth / OIDC depth** — OIDC discovery, implicit grant detection, redirect_uri validation weaknesses (error-differential oracle, pre-auth), missing `state` (CSRF).
- **Many bypasses** — 403/401 engine: 51 path mutations × 29 header spoofs × 9 verbs + method-override. Every injection class carries a WAF-evasion payload set (21 SQL, 17 XSS, 32 cmd, multi-engine SSTI).
- **Chaining engine** — SQLi bypass→ATO, XSS→session theft→ATO, SSRF→cloud metadata→IAM creds, open-redirect→OAuth token theft, LFI→secret→escalation, JWT-forge→admin, mass-assign→admin, cache+XSS→mass-ATO, and more. Chains score highest in the report.

</details>

---

<details>
<summary><strong>🧠 Why It's Different</strong></summary>
<br>

Most recon scripts dump a flat list. Venator adds the parts that actually win bounties:

- **JS intelligence** — mines JS bundles for hidden API routes and leaked secrets (AWS, Google, Stripe, GitHub, Slack, JWT, private keys…).
- **Wayback / CDX mining** — keyless historical URL discovery; flags forgotten endpoints (`.env`, `.sql`, `/admin`, `?id=`).
- **Subdomain takeover** — dangling-CNAME detection against 17 service fingerprints (S3, GitHub Pages, Heroku, Fastly, Netlify…).
- **GraphQL introspection** — locates GraphQL endpoints and checks if the schema is exposed.
- **CVE → exploitation intel** — enriches detected CVEs with nuclei metadata (CVSS, PoC links) and optional `searchsploit` ExploitDB matches.
- **Validation pass** — re-confirms findings, detects soft-404s (the #1 false-positive source), and de-duplicates.
- **Catch-all / SPA-aware** — drops soft-404 artifacts, collapses cache-buster URL explosions, excludes transport endpoints. Reaches blank-value params and param-less endpoints SPAs only call at user-action time.
- **Bounty prioritization** — every finding is scored (severity + exploitability + asset value + confidence); report leads with a ranked "Hunt these first" list.
- **Active probing (lead generation)** — non-destructive 403/401 bypass matrix, open redirect, and error/signature-based injection leads. No data writes.
- **Modern CVE/technique checks** — Next.js CVE-2025-29927, web cache poisoning + host-header injection, email spoofing posture (SPF/DMARC).
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
- **Audit log** — every request (method, URL, timestamp, phase, status, tool) appended to `output/<target>/audit.jsonl`.
- **Non-destructive only** — GET/HEAD; benign canary tokens for reflection signals; read-only GraphQL introspection; no fuzzing, no credential brute, no DoS-style volume.
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

**nuclei** runs non-destructive tags only (`ssl,tech,exposure,misconfiguration,cve,takeover,cors`) and excludes `intrusive,dos,fuzz,brute-force,sqli,xss-injection`.

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

`--no-subdomains` `--no-dns` `--no-ports` `--no-probe` `--no-fingerprint` `--no-endpoints` `--no-vuln` `--no-nuclei` `--no-external` `--no-dir-brute` `--no-jsintel` `--no-wayback` `--no-takeover` `--no-graphql` `--no-validate` `--no-cve-intel` `--no-active` `--no-exploit` `--no-chain` `--no-apispec` `--no-parammine` `--no-sourcemap` `--no-blindxss`

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
subdomains → dns → ports → probe → fingerprint → endpoints
  → JS intel → recursive crawl (+katana) → headless browser (SPA + DOM-XSS)
  → wayback → takeover → favicon hash
  → vuln (headers, tls, cors, reflection, misconfig, graphql, CVE, email,
          exposure: .git / actuator / .env, nuclei)
  → active probing (403/401 bypass, open-redirect, CRLF, injection leads,
                    OAuth, Next.js CVE-2025-29927, cache poisoning)
  → exploitation (SQLi auth-bypass, XSS, command injection — PoC)
  → chaining → CVE intel → validation → bounty prioritization → report
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
- A finding is a *candidate*. Confirm manually, capture a minimal non-destructive proof, and follow the program's disclosure rules. For subdomain takeover, do **not** claim the resource — document and report it.
- A leaked-secret match is "possible" until verified. **Do not use** a found credential; report it for rotation.
- The **active phase generates leads, not exploits**. Never escalate to `UNION`/`OR 1=1`/time-based/RCE payloads on live data. Disable with `--no-active` where program rules require passive-only testing.
- Unauthorized scanning may be illegal in your jurisdiction. You are responsible for how you use this tool.

</details>

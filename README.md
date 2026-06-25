# reconscan

An **elite, modular CLI** for authorized reconnaissance and **non-destructive**
vulnerability detection — built to compress the slow part of bug-bounty hunting
(recon → triage → "what do I test first") into one rate-limited, audit-logged run.

Use **only** against assets you own or have explicit written permission to test.

> **reconscan actively confirms vulnerabilities** (login bypass, RCE, SSRF, XXE,
> XSS, mass-assignment, …) and chains them — run it **only** against targets you
> own or are explicitly authorized to test. It follows **proof-over-damage**:
> confirmations extract a *minimal* indicator (a boolean differential, an echoed
> marker, `id` output, an OOB callback) and **never dump, modify, corrupt, or
> destroy data**; secrets it finds are reported, never used. Gate the offensive
> phases with `--no-exploit` / `--no-chain` / `--no-active` where program rules
> require passive testing. Non-`confirmed` findings are **candidates** — verify
> them manually.

---

## Exploitation & chaining (not just recon)

reconscan **confirms** vulnerabilities by demonstrating impact, then **chains**
them into submittable, high-payout attack paths:

- 🔓 **Exploitation phase** (site-agnostic — auto-detects HTML forms **and** JSON
  APIs, no per-site config): **SQLi/NoSQLi auth bypass** on login forms and JSON
  login APIs, **mass-assignment** privilege escalation (inject `role=admin`),
  **reflected XSS** that proves it executes, **OS command injection** (`id` output),
  **local file inclusion / path traversal** (read-only — confirms only on a hard
  `root:…:0:0:` / `win.ini` signature or PHP `php://filter` base64 source, across
  encoded/`%00`-truncated/`....//` traversal ladders),
  **WAF-aware injection** — fingerprints the protecting WAF/CDN (Cloudflare, Akamai,
  Imperva, AWS, F5, ModSecurity, Sucuri…) and, when a probe is **blocked**, retries
  SQLi/XSS with re-spelled payloads (comment-split `/**/`, MySQL `/*!50000…*/`,
  keyword case-mix, operator swaps, base64 wraps) to confirm the bug is still reachable,
  **JWT** weaknesses (alg:none, weak-secret crack, no-exp), **IDOR** probing, and
  **sensitive-data exposure** (Luhn-checked cards, private keys, bulk-PII). Each is
  marked `EXPLOITED` with a **copy-paste `curl` PoC**. When a login bypass yields a
  token, later checks run **authenticated** automatically. Proof-over-damage: it
  extracts a minimal indicator, never dumps or destroys data.
- 🧪 **Deep class coverage** — **broken auth** (default creds + user enum),
  **GraphQL** (introspection + sensitive-op flag + field suggestion + **schema
  recovery via clairvoyance** — when introspection is disabled, brute-forces the
  query root *read-only* and harvests "Did you mean…" errors to rebuild the field
  list, e.g. recovered 7 real DVGA fields with introspection off — **plus deep
  abuse**: alias-batching & array-batching rate-limit bypass, missing query
  depth/cost limit, **and resolver injection** — String arguments fuzzed for
  **OS command injection / RCE** (in-band `id` + blind OOB) and **error-based
  SQLi**, confirmed against OWASP DVGA's `systemDebug`/`importPaste`/`pastes`),
  **stored XSS**, **CSRF**, **SSTI→RCE** (8 template engines, confirms via `id`),
  **XXE** (in-band file read), **HTTP request smuggling** (CL.TE/TE.CL timing),
  and **WebSocket CSWSH** (cross-origin handshake — collapses a blanket "upgrades
  any path" server into one finding instead of spamming guessed paths).
- ✂️ **CRLF injection / response splitting** — injects percent-encoded CR/LF
  (incl. LF-only, double-encoded `%250d%250a`, overlong-UTF-8 `嘊嘍`) into
  redirect-style params and the path, and **confirms only** when a uniquely-named
  header it asked the server to emit (`X-Crlf-<rand>: <rand>` / split `Set-Cookie`)
  comes back as a **real parsed response header** — effectively zero false positives.
- 🧁 **Web cache deception** — with your `--auth-bearer`/cookie session, proves a
  route is private (authed 2xx / anon denied), requests it as a static-looking
  `…/x.css` (also `;x.css`, `%2f`), then **re-fetches that URL anonymously**: if a
  cache hands the private body (matched by an identity marker absent from the anon
  page) back to the unauthenticated client, it's a confirmed leak.
- ⏱️ **Blind SQLi** — when nothing reflects, confirms via **time-based** payloads
  (MySQL `SLEEP`, Postgres `pg_sleep`, MSSQL `WAITFOR`, Oracle `DBMS_PIPE`,
  SQLite) whose delay must **scale with the requested seconds** (re-confirmed so a
  slow page isn't a false positive), and via **OOB** primitives (MSSQL
  `xp_dirtree`, Oracle `UTL_HTTP`/`UTL_INADDR`, MySQL `LOAD_FILE`) that beacon the
  collaborator.
- 🪪 **JWT forge + replay confirmation** — actively forges tokens and replays them
  against a real authorization oracle (2xx-gated, so a shared 404 can't masquerade
  as one) to **prove** acceptance, with a **wrong-secret negative control** that
  separates true findings: **signature-not-verified** (any forged token works — as
  on OWASP crAPI), **RS256→HS256 algorithm confusion** (re-signs with the server's
  RSA public key as the HMAC secret, from JWKS / embedded `jwk`/`x5c`), **alg:none**,
  **embedded-`jwk` self-sign** (CVE-2018-0114 — supplies our own key in the header),
  **`kid` path-traversal** (→ `/dev/null` empty key), and **jku/x5u header injection**
  (points the key URL at the OOB host — a callback proves the server fetches an
  attacker-controlled signing key). Seeds the oracle from a captured login token **or**
  your `--auth-bearer` session. Plus **OAuth `redirect_uri` tampering** and
  **password-reset host-header poisoning**.
- 🎯 **API authorization + SSRF** (OWASP API Top-10 core, proven on OWASP crAPI):
  **BOLA / IDOR** — enumerates id-keyed object endpoints with your session and
  confirms broken object authorization when distinct **other users' PII** comes
  back per id (kills the static-page false positive); **JSON-body SSRF** — *learns
  the request body from the API's own validation errors*, injects into URL-typed
  fields, and confirms **in-band** (cloud-metadata/`/etc/passwd` signature or
  reflected fetch) **or blind** via OOB callback.
- 📡 **Out-of-band (OOB) — confirms BLIND bugs** that never echo in the response:
  spins up an **interactsh** collaborator (DNS + HTTP, with **ngrok** fallback),
  plants per-injection callback URLs, and confirms **blind SSRF**, **blind OS
  command injection (RCE)**, **blind XXE** (external DTD), and **blind/stored XSS**
  the moment the target — or a victim's browser — calls home. Stored-XSS payloads
  that fire later are reported so you can keep watching your OOB host.
- 🔑 **Authenticated scanning** — pass `--cookie`, `--auth-bearer`, or `--header`
  and **every phase runs as a logged-in user** (most real bugs sit *behind* login).
  A mid-scan captured token never clobbers your supplied session.
- 🗺️ **Surface expansion** — a **recursive in-scope crawler** (BFS over HTML:
  `<a>`/`<form>`/`<link>`/`<iframe>` + meta-refresh, bounded by depth + page budget
  + a per-`(host,path)` variant cap so parameter permutations can't trap it) that
  **merges every URL, form, and parameter it finds back into the surface** so the
  injectors / IDOR / LFI / clairvoyance phases chew a far wider attack surface —
  optionally accelerated by **katana** when the binary is present (its output is
  re-filtered through the scope guard); plus **hidden-parameter discovery**
  (Arjun-style: mines params the app reads but never advertises, then feeds them to
  the injectors), **OpenAPI/Swagger ingestion** (parses the spec → every documented
  path+param becomes attack surface), and **JS source-map recovery** (reconstructs
  original source from `.map` files for deeper secret/endpoint mining) + **DOM-XSS**
  source→sink leads.
- 🖥️ **Headless-browser phase** — a real Chromium (Playwright) renders the
  JavaScript the static crawler can't: **SPA routes + the XHR/fetch endpoints the
  app actually calls** are captured post-render and merged back into the surface
  (on OWASP Juice Shop this surfaced `/api/Challenges/?name=…` and a
  `/redirect?to=…` open-redirect the static pass never sees). It also does
  **execution-confirmed DOM-XSS**: an init-script sentinel + alert/confirm/prompt
  hooks mean a finding fires only when the payload *actually runs* in the browser
  (parameter and `location.hash` sinks) — zero-FP, not a source→sink guess. Every
  browser request is routed through a guard that aborts anything off-scope. Self-
  disabling: auto-skips cleanly if Playwright/Chromium isn't installed.
- 🗂️ **Exposure extraction** — confirms the classic "internals on the doormat"
  leaks with **zero-FP structural checks + a random-sibling negative control**: a
  reachable **`.git/`** directory (validates the ref shape + `[core]` section, then
  extracts the remote URL and last-commit author — never clones the repo), a served
  **`.env`** (KEY=VALUE shape; reports the sensitive key *names*, never the values),
  **Spring Boot actuator** endpoints (`/actuator/env`, `/heapdump` — declared from
  headers without downloading the dump — `/threaddump`, `/configprops`, `/beans`,
  `/mappings`), **`.svn`** metadata, and Apache **`/server-status`**. Found a real
  `.env` with live DB/Mongo credentials on OWASP crAPI.
- 🔗 **OAuth / OIDC depth** — pulls the **OIDC discovery document**
  (`.well-known/openid-configuration`) to map the flow and flags a still-enabled
  implicit grant, then confirms **`redirect_uri` validation weaknesses** (one-click
  ATO) with an **error-differential oracle that works pre-auth**: the app's real
  redirect must be accepted, an unrelated host must be rejected, and classic
  confusion shapes (subdomain-suffix, path-embed, `@`-userinfo) that smuggle the
  *same* attacker host past the check are reported only when **not rejected AND
  reflected back** — plus a **missing-`state` (CSRF)** signal. Benign: never
  completes a flow or follows the off-scope redirect.
- 🛡️ **Many bypasses, not one** — the 403/401 engine alone tries 51 path
  mutations × 29 spoofable headers × 9 verbs + method-override + case toggles, and
  every injection class carries a broad WAF-evasion payload set (21 SQL, 17 XSS,
  32 cmd, multi-engine SSTI) so a blocked payload just falls through to the next.
- 🧬 **Chaining engine** — assembles the chains vendors actually pay for: SQLi
  bypass→ATO, XSS→session-theft→ATO, SSRF→cloud-metadata→IAM creds,
  open-redirect→OAuth token theft, LFI→source/secret→escalation, JWT-forge→admin,
  mass-assign→admin, leaked-key→API, Next.js bypass→admin, takeover→OAuth,
  cache+XSS→mass-ATO. Chains lead the report (scored highest).
- 🛟 **Scales safely** — `--max-requests` global budget caps runaway traffic on
  large multi-subdomain runs; `-q` keeps output signal-dense.

> Use **only** against targets you're authorized to test (programs you're in, or
> deliberately-vulnerable labs like OWASP Juice Shop / `demo.testfire.net`). Disable
> with `--no-exploit` / `--no-chain` where program rules require passive testing.

## Why it's different

Most recon scripts dump a flat list and leave you to sort it out. reconscan adds
the parts that actually win bounties:

- 🧠 **JS intelligence** — pulls the site's JavaScript bundles and mines them for
  hidden API routes and **leaked secrets** (AWS, Google, Stripe, GitHub, Slack,
  JWT, private keys, …). Modern SPAs leak their whole API surface in JS.
- 🕰️ **Wayback / CDX mining** — keyless historical-URL discovery; flags "juicy"
  forgotten endpoints (`.env`, `.sql`, `/admin`, `?id=`, `.well-known/...`).
- 🪝 **Subdomain takeover** — dangling-CNAME detection against 17 service
  fingerprints (S3, GitHub Pages, Heroku, Fastly, Shopify, Netlify, …).
- 🔎 **GraphQL introspection** — locates GraphQL endpoints and checks (read-only)
  whether the schema is exposed.
- 🎯 **CVE → exploitation intel** — when a CVE is detected, it enriches it with
  local nuclei-template metadata (CVSS, description, PoC links), optional
  `searchsploit` ExploitDB matches, and reference URLs — the research step before
  manual reproduction.
- ✅ **Validation pass** — re-confirms findings against the live target, detects
  **soft-404s** (the #1 false-positive source), and de-duplicates, so the report
  is signal not noise.
- 🧱 **Catch-all / SPA-aware** — on hosts that serve `200 + index` for *every*
  path (Next.js, Juice-Shop-style apps), the surface builders drop relative-URL
  **soft-404 artifacts** (`/.env/socket.io/` …), collapse cache-buster URL
  explosions, and exclude transport endpoints (socket.io/webpack-hmr) from the
  injection surface — so the request budget hunts real endpoints instead of ghosts.
  Injection reaches **blank-value params** (`?q=`) and **param-less search/API
  endpoints** the SPA only calls at user-action time, and SQLi fingerprints include
  the **SQLite / Node-ORM** errors those apps emit. The SSRF oracle strips the
  reflected payload first, so an app that merely **echoes** a rejected URL can't fake
  a cloud-metadata hit.
- 🥇 **Bounty prioritization** — every finding is scored (severity +
  exploitability + asset value + confidence) and the report leads with a ranked
  **"Hunt these first"** list.
- 🧨 **Active probing (lead generation)** — benign, non-destructive checks that
  surface *exploitable classes* for manual follow-up: **403/401 bypass matrix**
  (path mutations, trusted-header spoofs, safe method swaps), **open redirect**,
  and **error/signature-based injection** (SQLi error strings, SSTI `{{7*7}}`→49,
  path traversal `root:x:`, reflected-XSS raw-metachar). No exploitation, no
  blind/time-based payloads, no data writes. Each hit is a lead, scored high.
- ⚡ **Modern, targeted CVE/technique checks** — **Next.js CVE-2025-29927**
  middleware auth-bypass (`x-middleware-subrequest`, version-gated), **web cache
  poisoning + host-header injection** (unkeyed-header reflection, cacheable-gated,
  cache-buster-safe), and **email spoofing posture** (SPF/DMARC weakness, pure DNS).
- 🧭 **Wildcard-DNS-aware subdomain enum** — detects wildcard records and drops
  the brute-forced ghosts they create (the #1 subdomain false-positive source).
- 🎯 **Favicon mmh3 hash** — Shodan/FOFA pivot to find sibling hosts and origins
  no DNS brute will surface (pure-Python, no dependency).
- 🤫 **Scales to many subdomains** — `-q` quiet mode collapses per-request noise;
  off-scope + duplicate services are deduped so output stays signal-dense.
- 🎭 **Random User-Agent rotation** — realistic browser UAs rotated per request.

---

## Safety model (enforced in code, not by convention)

- **Scope guard** — only the target apex, its subdomains, and `--extra-scope`
  hosts are ever contacted. Out-of-scope URLs raise `ScopeError`, are logged as
  `BLOCKED_OUT_OF_SCOPE`, and dropped. (OSINT sources like crt.sh / Wayback are
  queried directly, then their results are scope-filtered before any probing.)
- **Global rate limiter** — one thread-safe limiter spaces *all* outbound
  requests by `--delay` (or `1/--rate-limit`). More threads ≠ more req/sec.
- **Audit log** — every request (method, URL, ISO timestamp, phase, status, tool)
  appended to `output/<target>/audit.jsonl`. External tools logged too.
- **Non-destructive only** — GET/HEAD; benign canary tokens for reflection
  signals; read-only GraphQL introspection; no fuzzing, no credential brute, no
  DoS-style volume.
- **Degraded-run detection** — if every live host fails HTTP probing, the report
  is flagged `DEGRADED RUN` instead of silently looking "clean".

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10+. Pure-Python fallbacks mean it runs with zero external binaries.
These make it faster/deeper if on `PATH`: `subfinder`, `httpx`, `nuclei`, `nmap`,
`masscan`, `openssl`, `dig`, `katana` (crawl accelerator), and `searchsploit`
(ExploitDB CLI, for offline PoC paths). No tool requiring an API key is used.
The **headless-browser phase** (SPA render + DOM-XSS) is optional — it activates
when Playwright is installed (`pip install playwright` + a Chromium/Chrome on the
box) and auto-skips otherwise; disable explicitly with `--no-browser`. `nuclei` runs with non-destructive
template tags only (`ssl,tech,exposure,misconfiguration,cve,takeover,cors`),
excludes `intrusive,dos,fuzz,brute-force,sqli,xss-injection`, and disables OOB
interactsh.

---

## Usage

```bash
python3 reconscan.py <apex-domain> [options]
```

On start it prints the legal banner and asks you to **type the apex domain** to
confirm authorization (skip with `--yes` in automation you control).

### Example commands

```bash
# 1. Conservative full scan (1 req/sec, every phase)
python3 reconscan.py example.com

# 2. Faster scan against your own infra, custom output dir
python3 reconscan.py example.com --yes --delay 0.3 -o output/example

# 3. Fast triage: skip slow subdomain enum, ports, and nuclei
python3 reconscan.py example.com --yes --no-subdomains --no-ports --no-nuclei

# 4. Deep recon only (no vuln phase), but keep JS + Wayback + takeover
python3 reconscan.py example.com --no-vuln

# 5. JS-secret hunt focus: more JS files, no dir brute noise
python3 reconscan.py example.com --js-max-files 60 --no-dir-brute

# 6. Full deep run with nuclei tuned for your own infra (10-min cap)
python3 reconscan.py example.com --yes --delay 0.2 \
    --nuclei-rate 40 --nuclei-timeout 600 --max-hosts 40

# 7. Stealthier: rotate UAs (default on), slower, single host
python3 reconscan.py example.com --delay 1.5 --no-subdomains

# 8. Pure recon, no external binaries (pure-Python fallbacks)
python3 reconscan.py example.com --no-vuln --no-external
```

### Flags

**Politeness / safety**
| Flag | Default | Meaning |
|------|---------|---------|
| `--delay <s>` | `1.0` | Seconds between *every* request (global). |
| `--rate-limit <n>` | — | Max req/sec (stricter of this vs `--delay` wins). |
| `--timeout <s>` | `10.0` | Per-request timeout. |
| `--threads <n>` | `5` | Per-phase HTTP concurrency cap (rate limiter still bounds throughput). |
| `--workers <n>` | `0` (auto) | Parallel phase workers; `0` auto-scales to CPU count. Overlaps independent work (nuclei/nmap/wayback/DNS) for wall-clock speedup. |
| `--verify-tls` | off | Verify TLS certs on requests. |
| `--no-rotate-ua` | off | Disable per-request random User-Agent rotation. |
| `-y, --yes` | off | Skip the typed authorization confirmation. |
| `--extra-scope <h,h>` | — | Extra in-scope hosts you own (comma-separated). |
| `-q, --quiet` | off | Quiet output (summaries only) — best for many subdomains. |
| `-v, --verbose` | off | Verbose (per-request detail, blocked off-scope hosts). |

**Authenticated scanning** (most bugs sit *behind* login)
| Flag | Default | Meaning |
|------|---------|---------|
| `--cookie "<c>"` | — | Session cookie(s) sent on every request, e.g. `"session=abc; csrf=xyz"`. |
| `--auth-bearer <tok>` | — | Adds `Authorization: Bearer <tok>` to every request. |
| `--header "K: V"` | — | Extra header on every request (repeatable). |

**Out-of-band (OOB)** — confirms blind bugs
| Flag | Default | Meaning |
|------|---------|---------|
| `--no-oob` | off | Disable the OOB collaborator (blind SSRF/RCE/XXE/XSS off). |
| `--oob-provider <p>` | `auto` | `auto` (interactsh→ngrok), `interactsh`, or `ngrok`. |
| `--ngrok-domain <d>` | — | Reserved ngrok domain for the OOB fallback. |

**Phase toggles** — `--no-subdomains`, `--no-dns`, `--no-ports`, `--no-probe`,
`--no-fingerprint`, `--no-endpoints`, `--no-vuln`, `--no-nuclei`, `--no-external`,
`--no-dir-brute`, `--no-jsintel`, `--no-wayback`, `--no-takeover`, `--no-graphql`,
`--no-validate`, `--no-cve-intel`, `--no-active`, `--no-exploit`, `--no-chain`,
`--no-apispec`, `--no-parammine`, `--no-sourcemap`, `--no-blindxss`.

**Knobs**
| Flag | Default | Meaning |
|------|---------|---------|
| `--ports <list>` | common set | Comma-separated ports to scan. |
| `--dns-wordlist <file>` | built-in | Subdomain brute wordlist. |
| `--dir-wordlist <file>` | built-in | Directory brute wordlist. |
| `--max-hosts <n>` | `25` | Cap hosts for port + vuln scanning. |
| `--nuclei-rate <n>` | derive | nuclei requests/sec. |
| `--nuclei-timeout <s>` | `900` | Max seconds for the nuclei phase (partial output kept). |
| `--js-max-files <n>` | `25` | Max JS files to fetch + analyze. |
| `--wayback-limit <n>` | `5000` | Max Wayback/CDX rows to request. |

---

## Performance & parallelism

The scan auto-detects CPU count and runs **independent phases concurrently**:
subdomain enum ∥ DNS ∥ Wayback at start; nmap port scan ∥ HTTP probing; and the
slow **nuclei** phase overlaps the Python vuln checks instead of running after
them. Tune with `--workers` (`0` = auto).

## Pipeline (phase order)

```
subdomains → dns → ports → probe → fingerprint → endpoints
  → JS intel → recursive crawl (+katana) → headless browser (SPA render + DOM-XSS)
  → wayback → takeover
  → favicon hash
  → vuln (headers, tls, cors, reflection, misconfig, graphql, version-CVE, email,
          exposure: .git/actuator/.env, nuclei)
  → active probing (403/401 bypass, open-redirect, CRLF, injection leads,
                    OAuth redirect_uri/state, Next.js CVE-2025-29927,
                    cache poisoning / host-header)
  → exploitation (SQLi auth-bypass, reflected-XSS execute, command-injection — PoC)
  → chaining (assemble high-impact attack paths)
  → CVE exploitation intel
  → validation / false-positive filtering
  → bounty prioritization → report
```

## Output

```
output/<target>/
├── audit.jsonl          # every request: method, url, timestamp, status, phase, tool
└── report.json          # full machine-readable results

reports/<root>/
├── scan_report.md       # for an AI/LLM to consume
└── scan_report.html     # styled dashboard for a human to read
```

Two human/agent reports by design: the **`.md`** is clean text for piping into an
LLM; the **`.html`** is a self-contained dark dashboard (severity bars, ranked
"Hunt these first", filterable finding cards, recon tables, favicon Shodan pivots)
— no external assets, just open it in a browser. Both lead with run warnings, the
ranked hunt list, and findings (priority score + validation status).

---

## Responsible use

- Only scan assets you **own** or have **explicit written authorization** to test.
  Stay inside program scope. `--extra-scope` is for *your* assets, not for reaching
  outside a program's scope.
- Keep `audit.jsonl` — it's your evidence of what was done, when, against what.
- A finding is a *candidate*. Confirm manually, capture a minimal non-destructive
  proof, and follow the program's disclosure rules. Never escalate beyond
  confirming impact. For subdomain takeover, do **not** claim the resource —
  document and report.
- A leaked-secret match is "possible" until you verify it. **Do not use** a found
  credential; if real, the right action is to report it for rotation.
- The **active phase generates leads, not exploits**. A SQLi/SSTI/LFI/XSS/bypass
  signal means the class is worth manual work — confirm with a minimal, balanced,
  non-destructive PoC. Never escalate to UNION/`OR 1=1`/time-based/RCE payloads on
  live data. Disable it entirely with `--no-active` where program rules require
  passive-only testing.
- Unauthorized scanning may be illegal in your jurisdiction. You are responsible
  for how you use this tool.

"""Built-in wordlists, fingerprint signatures, and security-header specs.

Kept intentionally small (no DoS-scale brute force). Override via CLI flags.
"""
from __future__ import annotations

import re

# ----------------------------------------------------------- user-agent pool
# Realistic, current desktop/mobile browser UAs. Rotated per-request when
# rotation is enabled, so a target's trivial UA-based blocking doesn't tank
# the whole scan. Still rate-limited + scope-gated.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

# ------------------------------------------------------- subdomain brute words
SUBDOMAIN_WORDS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp",
    "secure", "vpn", "admin", "portal", "api", "dev", "staging", "stage", "test",
    "demo", "app", "apps", "m", "mobile", "shop", "store", "cdn", "static",
    "assets", "img", "images", "media", "files", "ftp", "sftp", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "wiki", "docs", "support", "help",
    "status", "monitor", "grafana", "kibana", "prometheus", "db", "database",
    "mysql", "postgres", "redis", "cache", "internal", "intranet", "corp",
    "vpn2", "gateway", "gw", "proxy", "lb", "auth", "sso", "login", "account",
    "accounts", "billing", "pay", "payment", "payments", "checkout", "book",
    "booking", "bookings", "reserve", "reservations", "events", "event",
    "newsletter", "news", "cms", "wp", "wordpress", "old", "new", "beta",
    "alpha", "qa", "uat", "preprod", "prod", "staging2", "backup", "bak",
    "host", "hosting", "panel", "cpanel", "whm", "webdisk", "autodiscover",
    "autoconfig", "owa", "exchange", "lync", "sip", "voip", "pbx", "ns",
    "dns", "mx", "mx1", "mx2", "email", "smtp2", "imap", "pop", "pop3",
]

# ------------------------------------------------------------- directory words
DIR_WORDS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "user",
    "users", "account", "dashboard", "panel", "cpanel", "phpmyadmin",
    "config", "config.php", "configuration", "setup", "install", "installer",
    "backup", "backups", "bak", "old", "tmp", "temp", "test", "dev", "debug",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "openapi.json",
    "actuator", "actuator/health", "metrics", "status", "server-status",
    "server-info", "info.php", "phpinfo.php", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "uploads", "upload", "files", "download", "downloads", "assets", "static",
    "media", "images", "img", "js", "css", "vendor", "node_modules",
    "console", "manage", "management", "private", "secret", "internal",
    "readme.txt", "readme.md", "changelog.txt", "license.txt", "web.config",
    ".env", ".env.local", ".env.bak", ".git/HEAD", ".git/config", ".svn/entries",
    ".hg", ".DS_Store", "composer.json", "package.json", "yarn.lock",
    "docker-compose.yml", "Dockerfile", ".dockerignore", ".htaccess",
    "error_log", "errors.log", "debug.log", "logs", "log",
]

# Sensitive paths that are findings on their own if reachable (status<400-ish).
SENSITIVE_PATHS = {
    "/.git/HEAD": ("Exposed .git repository", "high",
                   "Download repo history with git-dumper; rotate any secrets in history."),
    "/.git/config": ("Exposed .git config", "high",
                     "Confirm repo accessibility; remove from webroot."),
    "/.env": ("Exposed .env file", "critical",
              "Check for live credentials; rotate immediately and block path."),
    "/.env.local": ("Exposed .env.local", "critical",
                    "Check for live credentials; rotate and block."),
    "/.env.bak": ("Exposed .env backup", "critical",
                  "Rotate credentials; remove backup from webroot."),
    "/.svn/entries": ("Exposed .svn metadata", "high",
                      "Block .svn; rotate any leaked secrets."),
    "/.DS_Store": ("Exposed .DS_Store (dir listing leak)", "low",
                   "Parse with ds_store tool to enumerate filenames; remove file."),
    "/web.config": ("Exposed web.config", "medium",
                    "May leak connection strings/config; restrict access."),
    "/.htaccess": ("Exposed .htaccess", "low",
                   "Server may be serving dotfiles; review server config."),
    "/server-status": ("Apache mod_status exposed", "medium",
                       "Reveals live requests/IPs; restrict to localhost."),
    "/actuator": ("Spring Boot Actuator exposed", "high",
                  "Enumerate /actuator/env,/heapdump; secure actuator endpoints."),
    "/actuator/health": ("Spring Boot Actuator (health) exposed", "medium",
                         "Check other actuator endpoints; secure them."),
    "/phpinfo.php": ("phpinfo() exposed", "medium",
                     "Leaks env/paths/modules; remove the file."),
    "/info.php": ("phpinfo() exposed (info.php)", "medium",
                  "Leaks env/paths; remove the file."),
    "/.well-known/security.txt": ("security.txt present", "info",
                                  "Informational — note the contact channel."),
    "/swagger-ui": ("Swagger UI exposed", "low",
                    "Maps API surface; review whether it should be public."),
    "/openapi.json": ("OpenAPI spec exposed", "low",
                      "Maps API surface; review exposure."),
}

# --------------------------------------------------------- security headers
# name -> (severity_if_missing, advice)
SECURITY_HEADERS = {
    "strict-transport-security": ("medium",
        "Add HSTS (e.g. max-age=31536000; includeSubDomains) to force HTTPS."),
    "content-security-policy": ("medium",
        "Add a CSP to mitigate XSS/data injection."),
    "x-frame-options": ("low",
        "Set X-Frame-Options: DENY or use CSP frame-ancestors to stop clickjacking."),
    "x-content-type-options": ("low",
        "Set X-Content-Type-Options: nosniff to stop MIME sniffing."),
    "referrer-policy": ("low",
        "Set Referrer-Policy (e.g. strict-origin-when-cross-origin)."),
    "permissions-policy": ("info",
        "Consider Permissions-Policy to restrict powerful browser features."),
}

# Headers that often leak version/stack info.
INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                     "x-aspnetmvc-version", "x-generator", "via", "x-drupal-cache"]

# --------------------------------------------------------- tech fingerprints
# Matched against response headers/body. (label, where, pattern_is_substring)
HEADER_TECH = [
    ("cloudflare", "server", "cloudflare"),
    ("nginx", "server", "nginx"),
    ("apache", "server", "apache"),
    ("microsoft-iis", "server", "iis"),
    ("litespeed", "server", "litespeed"),
    ("openresty", "server", "openresty"),
    ("php", "x-powered-by", "php"),
    ("asp.net", "x-powered-by", "asp.net"),
    ("express", "x-powered-by", "express"),
    ("next.js", "x-powered-by", "next.js"),
    ("varnish", "via", "varnish"),
    ("amazon-s3", "server", "amazons3"),
    ("amazon-cloudfront", "server", "cloudfront"),
    ("akamai", "server", "akamai"),
    ("vercel", "server", "vercel"),
    ("gunicorn", "server", "gunicorn"),
    ("werkzeug", "server", "werkzeug"),
    # Next.js App Router exposes itself via the Vary header (RSC / router hints)
    ("next.js", "vary", "next-router"),
    ("next.js", "vary", "rsc"),
    ("next.js", "x-powered-by", "next.js"),
]

# Tech detected purely by the PRESENCE of a (often vendor-specific) header,
# regardless of value. label is recorded when the header exists & is non-empty.
HEADER_PRESENCE_TECH = {
    "x-railway-edge": "railway",
    "x-railway-request-id": "railway",
    "x-vercel-id": "vercel",
    "x-vercel-cache": "vercel",
    "x-amz-cf-id": "amazon-cloudfront",
    "x-amz-request-id": "amazon-s3",
    "x-served-by": "fastly/varnish",
    "x-shopify-stage": "shopify",
    "x-drupal-dynamic-cache": "drupal",
    "x-generator": "generator-header",
}

# Matched against HTML body (label, substring)
BODY_TECH = [
    ("wordpress", "/wp-content/"),
    ("wordpress", "/wp-includes/"),
    ("drupal", "drupal-settings-json"),
    ("drupal", "/sites/default/files"),
    ("joomla", "/media/jui/"),
    ("joomla", "joomla"),
    ("magento", "/static/version"),
    ("magento", "mage/cookies"),
    ("shopify", "cdn.shopify.com"),
    ("react", "data-reactroot"),
    ("react", "__reactcontainer"),
    ("vue.js", "data-v-app"),
    ("angular", "ng-version"),
    ("next.js", "__next_data__"),
    ("next.js", "/_next/"),
    ("next.js", "self.__next_f"),
    ("nuxt", "__nuxt"),
    ("jquery", "jquery"),
    ("bootstrap", "bootstrap"),
    ("google-recaptcha", "recaptcha"),
    ("google-analytics", "google-analytics.com"),
    ("google-tag-manager", "googletagmanager.com"),
    ("cloudflare-challenge", "cf-challenge"),
]

# Regexes to extract version strings from common JS includes.
JS_VERSION_PATTERNS = [
    ("jquery", r"jquery[.\-/]?(\d+\.\d+(?:\.\d+)?)"),
    ("bootstrap", r"bootstrap[.\-/]?(\d+\.\d+(?:\.\d+)?)"),
    ("angular", r"angular[.\-/]?(\d+\.\d+(?:\.\d+)?)"),
    ("react", r"react[.\-@/]?(\d+\.\d+(?:\.\d+)?)"),
]

# Tiny built-in "known-risky version" heuristic map (NOT a full CVE DB —
# flags well-known EOL/vulnerable ranges for manual confirmation).
VERSION_ADVISORIES = [
    # (tech, predicate(version_tuple)->bool, note, severity)
    ("jquery", lambda v: v < (3, 5, 0),
     "jQuery < 3.5.0 has known XSS issues (CVE-2020-11022/11023).", "medium"),
    ("jquery", lambda v: v < (1, 9, 0),
     "jQuery < 1.9 is very old with multiple known issues.", "medium"),
    ("bootstrap", lambda v: v < (3, 4, 0),
     "Bootstrap < 3.4.0 has XSS in data-* (CVE-2018-14041 etc).", "medium"),
    ("bootstrap", lambda v: (4, 0, 0) <= v < (4, 3, 1),
     "Bootstrap 4.x < 4.3.1 has XSS issues (CVE-2019-8331).", "medium"),
    ("angular", lambda v: v < (1, 6, 0),
     "AngularJS 1.x is EOL and unsupported.", "medium"),
]

# ---------------------------------------------------- secret patterns (JS intel)
# (label, severity, compiled-regex). High-confidence patterns only, to keep the
# false-positive rate low. Matched against fetched JS / inline scripts / HTML.
# Detection only — secrets are reported, never used.
SECRET_PATTERNS = [
    ("AWS Access Key ID", "critical", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16})\b")),
    ("AWS Secret Access Key", "critical", re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]")),
    ("Google API Key", "high", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("Google OAuth Client Secret", "high", re.compile(r"\b(GOCSPX-[0-9A-Za-z\-_]{28})\b")),
    ("Firebase Cloud Messaging key", "high", re.compile(r"\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b")),
    ("Stripe Live Secret Key", "critical", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b")),
    ("Stripe Restricted Key", "high", re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,})\b")),
    ("GitHub Token", "critical", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{36,})\b")),
    ("GitLab PAT", "high", re.compile(r"\b(glpat-[0-9A-Za-z\-_]{20})\b")),
    ("Slack Token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("Slack Webhook", "medium", re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)")),
    ("Twilio Account SID", "high", re.compile(r"\b(AC[0-9a-fA-F]{32})\b")),
    ("SendGrid API Key", "critical", re.compile(r"\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b")),
    ("Mailgun API Key", "high", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b")),
    ("Private Key block", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT (HS/RS) token", "low", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("Square Access Token", "high", re.compile(r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b")),
    ("Heroku API Key", "high", re.compile(r"(?i)heroku.{0,20}?['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]")),
    ("npm Access Token", "critical", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("DigitalOcean Token", "critical", re.compile(r"\b(do[oprt]_v1_[a-f0-9]{64})\b")),
    ("OpenAI API Key", "high", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{40,})\b")),
    ("Telegram Bot Token", "medium", re.compile(r"\b([0-9]{8,10}:AA[A-Za-z0-9_-]{32,})\b")),
    ("Figma Token", "medium", re.compile(r"\b(figd_[A-Za-z0-9_-]{40,})\b")),
    ("Postman API Key", "high", re.compile(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b")),
    ("Cloudflare API Token", "high", re.compile(r"(?i)cloudflare.{0,24}?['\"]([A-Za-z0-9_-]{40})['\"]")),
    ("Shopify Access Token", "critical", re.compile(r"\b(shpat_[a-fA-F0-9]{32})\b")),
    ("Generic API key assignment", "medium", re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token|passwd|password)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{16,64})['\"]")),
]

# Strings that strongly indicate a value is a placeholder, not a live secret —
# used to suppress obvious false positives from the generic patterns.
SECRET_PLACEHOLDERS = [
    "your_", "example", "xxxx", "placeholder", "changeme", "dummy", "test",
    "sample", "<", "{{", "}}", "0000000000", "1234567890", "abcdef", "redacted",
]

# --------------------------------------------------- CISA-KEV / in-the-wild CVEs
# A curated set of CVEs on CISA's Known Exploited Vulnerabilities catalogue (i.e.
# confirmed exploited in the wild) — the scorer bumps any finding referencing one
# so the report leads with what attackers are ACTUALLY using, not just high CVSS.
KEV_CVES = {
    # web frameworks / app servers
    "CVE-2021-44228", "CVE-2021-45046",                 # Log4Shell
    "CVE-2022-22965", "CVE-2022-22963",                 # Spring4Shell / Spring Cloud
    "CVE-2017-5638", "CVE-2018-11776", "CVE-2023-50164",  # Apache Struts
    "CVE-2021-41773", "CVE-2021-42013",                 # Apache path traversal/RCE
    "CVE-2025-29927",                                   # Next.js middleware auth bypass
    # Atlassian
    "CVE-2022-26134", "CVE-2023-22515", "CVE-2023-22518", "CVE-2021-26084",  # Confluence
    "CVE-2019-11581", "CVE-2022-0540",                  # Jira
    # GitLab / Jenkins / VCS+CI
    "CVE-2021-22205", "CVE-2023-7028",                  # GitLab RCE / account takeover
    "CVE-2024-23897", "CVE-2018-1000861",               # Jenkins
    # edge / VPN / file transfer (mass-exploited)
    "CVE-2023-3519", "CVE-2019-19781", "CVE-2023-4966",  # Citrix NetScaler
    "CVE-2023-46805", "CVE-2024-21887", "CVE-2025-0282", "CVE-2025-22457",  # Ivanti
    "CVE-2022-40684", "CVE-2023-27997", "CVE-2024-21762",  # Fortinet
    "CVE-2023-34362", "CVE-2024-5806",                  # MOVEit Transfer
    "CVE-2023-27350",                                   # PaperCut
    "CVE-2023-20198", "CVE-2023-20273",                 # Cisco IOS XE
    # Microsoft Exchange (ProxyLogon / ProxyShell)
    "CVE-2021-26855", "CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207",
    # PHP / misc
    "CVE-2024-4577", "CVE-2017-9841",                   # PHP-CGI argument injection / PHPUnit
}

# --------------------------------------------------- tech → version-CVE heuristics
# (product, max_vulnerable_version, cve, severity, note). A detected product whose
# version is BELOW max_vulnerable is flagged (tentative — confirm the exact build).
# CVEs that are also in KEV_CVES additionally get the in-the-wild priority bump.
TECH_CVES = [
    ("jira",       "8.4.0",  "CVE-2019-11581", "critical", "template injection → RCE"),
    ("confluence", "7.18.1", "CVE-2022-26134", "critical", "unauth OGNL injection → RCE (KEV)"),
    ("confluence", "8.5.4",  "CVE-2023-22518", "critical", "improper authorization → takeover (KEV)"),
    ("gitlab",     "16.7.2", "CVE-2023-7028",  "critical", "password reset to arbitrary email → ATO (KEV)"),
    ("gitlab",     "13.10.3", "CVE-2021-22205", "critical", "unauth ExifTool RCE (KEV)"),
    ("jenkins",    "2.442",  "CVE-2024-23897", "high",     "CLI arbitrary file read (KEV)"),
]

# Regexes for endpoints/paths referenced in JS (relative + absolute API paths).
ENDPOINT_PATTERNS = [
    re.compile(r"""['"`](/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|user|account|upload|download|webhook|callback)[A-Za-z0-9_\-/\.{}:]*)['"`]"""),
    re.compile(r"""['"`]((?:https?:)?/[A-Za-z0-9_\-/]+\.(?:json|xml|config|env|bak|sql|yaml|yml))['"`]"""),
    re.compile(r"""fetch\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""\.(?:get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]"""),
]

# --------------------------------------------------- subdomain takeover sigs
# (service, list-of-CNAME-needles, body-fingerprint, severity). A dangling CNAME
# pointing at an unclaimed service + the matching error body = takeover candidate.
TAKEOVER_SIGNATURES = [
    ("GitHub Pages", ["github.io"], "There isn't a GitHub Pages site here", "high"),
    ("AWS S3", ["s3.amazonaws.com", "s3-website", "amazonaws.com"], "NoSuchBucket", "high"),
    ("Heroku", ["herokuapp.com", "herokudns.com"], "No such app", "high"),
    ("Heroku (alt)", ["herokuapp.com"], "heroku | no such app", "high"),
    ("Fastly", ["fastly.net"], "Fastly error: unknown domain", "high"),
    ("Shopify", ["myshopify.com"], "Sorry, this shop is currently unavailable", "high"),
    ("Surge.sh", ["surge.sh"], "project not found", "high"),
    ("Bitbucket", ["bitbucket.io"], "Repository not found", "high"),
    ("Ghost", ["ghost.io"], "The thing you were looking for is no longer here", "medium"),
    ("Pantheon", ["pantheonsite.io"], "The gods are wise, but do not know of the site", "high"),
    ("Tumblr", ["domains.tumblr.com"], "Whatever you were looking for doesn't currently exist", "medium"),
    ("Wordpress", ["wordpress.com"], "Do you want to register", "medium"),
    ("Netlify", ["netlify.app", "netlify.com"], "Not Found - Request ID", "medium"),
    ("Readme.io", ["readme.io"], "Project doesnt exist... yet!", "medium"),
    ("Unbounce", ["unbouncepages.com"], "The requested URL was not found on this server", "medium"),
    ("Cargo", ["cargocollective.com"], "404 Not Found", "low"),
    ("Webflow", ["proxy-ssl.webflow.com", "webflow.io"], "The page you are looking for doesn't exist", "medium"),
]

# "Juicy" path/extension signals when mining historical (wayback) URLs.
JUICY_EXTENSIONS = (".json", ".xml", ".sql", ".bak", ".old", ".zip", ".tar.gz",
                    ".tgz", ".env", ".config", ".yml", ".yaml", ".log", ".txt",
                    ".gz", ".rar", ".7z", ".db", ".sqlite", ".pem", ".key",
                    ".pdf", ".xls", ".xlsx", ".csv", ".bson", ".swp")
JUICY_KEYWORDS = ("admin", "internal", "debug", "test", "staging", "dev", "api",
                  "graphql", "token", "key", "secret", "password", "backup",
                  "upload", "private", "config", "oauth", "callback", "redirect",
                  "sso", "auth", "account", "invoice", "payment", "user", "id=")

# Common GraphQL endpoints to check for introspection (read-only).
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
                 "/query", "/graphiql", "/graphql/console", "/api/gql"]

# =====================================================================
# ACTIVE PROBING (lead generation) — all benign + non-destructive.
# Crafted-but-harmless inputs that elicit a *signal* (error text, echo,
# arithmetic result, redirect) confirming a bug CLASS is worth manual work.
# No data-modifying payloads, no blind/time-based (no DB load), no RCE.
# =====================================================================

# 403/401 bypass — path mutations ({P} = the forbidden path, no leading slash).
# A broad matrix: prefix tricks, suffix tricks, separators, dot/slash games, and
# encoding variants. The point is breadth — if one normalization quirk is closed,
# another stack still trips. The bypass engine tries them in order, early-exits.
BYPASS_PATH_MUTATIONS = [
    # NOTE: no bare parent-escape (".../..") mutations — they normalize to "/"
    # and falsely "bypass" by hitting the homepage. The runtime also guards
    # against any mutation whose response collapses to root / soft-404.
    # trailing variants
    "/{P}/", "/{P}//", "/{P}/.", "/{P}/./", "/{P}%20", "/{P}%09",
    "/{P}%00", "/{P}.", "/{P}..;/", "/{P};/", "/{P};a=b", "/{P}?", "/{P}??",
    "/{P}#", "/{P}#x", "/{P}~", "/{P}/~", "/{P}.json", "/{P}.html", "/{P}.css",
    "/{P}.js", "/{P}/.randomstring", "/{P}%2f", "/{P}%2e", "/{P}%252f",
    "/{P}%23", "/{P}%3f", "/{P}\\", "/{P}.;/",
    # leading / prefix variants
    "/./{P}", "//{P}", "///{P}", "/%2e/{P}", "/%2f{P}", "/./{P}/./",
    "/.;/{P}", "/..;/{P}", "/;/{P}", "/{P}/.;/",
    # case + path-segment games
    "/{P}/..%2f{P}", "/{P}%20/", "/{P}%09/", "/{P}/%2e%2e/{P}",
    # double-slash + dot-encoding
    "/{P}/./", "/{P}/%2e/",
]
# 403/401 bypass — request headers some stacks trust for ACL / routing decisions.
# Many spoofable IP/host/url override headers + method-override + auth tricks.
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"}, {"X-Forwarded-Host": "localhost"},
    {"X-Originating-IP": "127.0.0.1"}, {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"}, {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"}, {"X-True-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"}, {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"}, {"Cluster-Client-IP": "127.0.0.1"},
    {"X-Original-URL": "/{P}"}, {"X-Rewrite-URL": "/{P}"},
    {"X-Override-URL": "/{P}"}, {"X-Forwarded-Path": "/{P}"},
    {"X-Forwarded-Proto": "https"}, {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Port": "443"}, {"Referer": "/{P}"},
    {"X-Original-Host": "127.0.0.1"}, {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Content-Length": "0"}, {"X-HTTP-Host-Override": "127.0.0.1"},
]
# Methods to try — content-retrieving verbs only. OPTIONS/TRACE/CONNECT/PROPFIND
# return metadata/empty bodies (not the protected resource) and cause false
# "bypasses", so they're excluded from the bypass set.
BYPASS_METHODS = ["POST", "PUT", "PATCH", "GETS"]
BYPASS_METHOD_OVERRIDE = ["X-HTTP-Method-Override", "X-HTTP-Method",
                          "X-Method-Override"]

# WAF / CDN fingerprints — (vendor, body regexes, header regexes). Used to flag a
# protecting WAF (informational recon signal) and to recognise a block response so
# the injection phase can fall back to evasion-encoded payloads.
WAF_SIGNATURES = [
    ("Cloudflare",
     [r"cf-challenge-form", r"Just a moment\.\.\.", r"Attention Required! \| Cloudflare",
      r"Sorry, you have been blocked", r"Cloudflare Ray ID:", r"Error 1020",
      r"cdn-cgi/challenge-platform", r"__cf_chl_tk"],
     [r"cf-ray", r"__cfduid", r"__cf_bm", r"cf-mitigated"]),
    ("AWS WAF",
     [r"<AccessDenied>", r"Request blocked.*AWS",
      r"<TITLE>ERROR: The request could not be satisfied"],
     [r"x-amzn-requestid", r"x-amzn-waf", r"x-amz-cf-id"]),
    ("Imperva/Incapsula",
     [r"_Incapsula_Resource", r"incident ID:", r"subject=WAF Block", r"visid_incap"],
     [r"incap_ses", r"visid_incap", r"x-cdn:\s*imperva", r"x-iinfo"]),
    ("Akamai",
     [r"AkamaiGHost", r"Reference #[0-9]", r"ak-bm-", r"Access Denied.*permission to access"],
     [r"akamai-x-", r"akamaighost", r"x-akamai"]),
    ("F5 BIG-IP ASM",
     [r"The requested URL was rejected", r"Please consult with your administrator",
      r"[Ss]upport ID:.*[0-9]{10}", r"support_id=[0-9]+"],
     [r"\bTS[0-9a-f]{6,}\b", r"x-waf-event"]),
    ("ModSecurity",
     [r"mod_security", r"ModSecurity", r"Not Acceptable!", r"NAXSI"], []),
    ("Sucuri",
     [r"Sucuri WebSite Firewall", r"Access Denied - Sucuri", r"Block reason:"],
     [r"x-sucuri-id", r"x-sucuri-cache"]),
    ("FortiWeb",
     [r"Powered by Fortinet", r"Attack ID:.*[0-9]", r"FortiWeb"], []),
    ("Barracuda",
     [r"Barracuda.*blocked", r"BNI__BARRACUDA", r"BNWeb"], [r"barra_counter_session"]),
    ("Wallarm", [r"nginx-wallarm", r"Wallarm"], []),
    ("Wordfence", [r"Generated by Wordfence", r"Wordfence.*blocked"], []),
]
# Generic block-page wording + status codes that signal a WAF rejection.
WAF_BLOCK_KEYWORDS = [
    r"access denied", r"request rejected", r"you have been blocked", r"forbidden",
    r"attention required", r"security violation", r"not acceptable",
    r"request blocked", r"malicious", r"this request has been blocked",
]
WAF_BLOCK_CODES = {403, 406, 409, 419, 429, 503}

# Open redirect — param names + a benign external canary (IANA reserved).
REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return",
                   "return_url", "returnTo", "dest", "destination", "continue",
                   "r", "u", "rurl", "target", "redir", "go", "out", "to",
                   "callback", "redirect_url"]
REDIRECT_CANARY = "https://example.com/recon-canary"
# A Location/refresh/body match against these = the canary host took effect.
REDIRECT_HOST_MARK = "example.com/recon-canary"

# Error-based SQLi — benign breakers (NO boolean/UNION/time payloads).
SQLI_PROBES = ["'", "\"", "')", "'\"", "`"]
SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax", "warning: mysql", "mysqli_",
    "unclosed quotation mark after the character string", "quoted string not properly terminated",
    "pg_query()", "postgresql", "psqlexception", "sqlite3.operationalerror",
    "sqlstate[", "ora-01756", "ora-00933", "odbc sql server driver",
    "microsoft odbc", "native client", "syntax error at or near",
    "supplied argument is not a valid mysql", "valid postgresql result",
    # SQLite (incl. the node sqlite3/better-sqlite3 driver used by many SPA APIs,
    # e.g. OWASP Juice Shop's product-search SQLi surfaces "SQLITE_ERROR: ...")
    "sqlite_error", "sqlite3.", "unrecognized token", "sqlitedatabaseerror",
    "unterminated quoted string",
    # Node ORM / driver wrappers (Sequelize/Knex/TypeORM) + MySQL/Java codes
    "sequelizedatabaseerror", "er_parse_error", "er_bad_field_error",
    "sqlexception", "com.mysql.jdbc", "org.hibernate.exception",
    "syntaxerrorexception",
]
# SSTI — arithmetic markers; a rendered 49/1337 = template injection.
SSTI_PROBES = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"),
               ("{{7*'7'}}", "7777777"), ("<%= 7*7 %>", "49")]
# Path traversal — read a world-readable file; signature = real file content.
TRAVERSAL_PROBES = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
]
# Specific LITERAL signatures (matched as substrings, NOT regex — earlier
# versions used these as regex and "[fonts]" became a char class matching any
# of f/o/n/t/s, which matched every page). Keep them long + unambiguous.
TRAVERSAL_SIGNS = ["root:x:0:0:", "daemon:x:1:1:", "bin:x:2:2:",
                   "; for 16-bit app support", "[mci extensions]",
                   "[boot loader]"]
# Reflected-XSS context probe — distinctive marker w/ raw HTML metachars.
# We never execute; we check whether < > " survive UNescaped in an HTML body.
XSS_MARKER_PARAMS = ["q", "s", "search", "query", "name", "id", "page",
                     "ref", "redirect", "lang", "msg", "error", "keyword"]

# =====================================================================
# PARAMETER DISCOVERY (Arjun-style hidden-parameter mining)
# A param the app reads but doesn't advertise is fresh, untested attack
# surface — feed any we find into the exploit modules. Names ranked by how
# often they unlock injection/IDOR/SSRF/redirect surface.
# =====================================================================
PARAM_WORDS = [
    # generic
    "id", "page", "q", "query", "search", "s", "keyword", "name", "type",
    "category", "cat", "action", "do", "op", "mode", "view", "format", "lang",
    "locale", "sort", "order", "filter", "limit", "offset", "start", "count",
    "from", "to", "date", "year", "month", "day", "key", "value", "val", "data",
    # injection-prone
    "file", "filename", "path", "dir", "folder", "doc", "document", "template",
    "include", "inc", "page_id", "item", "item_id", "product", "product_id",
    "pid", "uid", "user", "user_id", "userid", "account", "account_id", "aid",
    "oid", "order_id", "ref", "reference", "code", "token", "hash", "sig",
    "signature", "callback", "jsonp", "cb",
    # ssrf / redirect-prone
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "return", "returnto", "return_url", "next", "continue",
    "target", "host", "domain", "site", "feed", "fetch", "load", "image", "img",
    "avatar", "icon", "proxy", "webhook", "out", "go", "open", "window",
    # auth / state
    "email", "username", "login", "password", "role", "admin", "is_admin",
    "debug", "test", "preview", "draft", "status", "state", "active", "enable",
    "disable", "show", "hide", "public", "private", "api_key", "apikey",
    "access_token", "session", "sessionid", "csrf", "_token", "auth",
    # content / xss-prone
    "message", "msg", "comment", "text", "title", "subject", "body", "content",
    "desc", "description", "note", "feedback", "input", "output", "html", "json",
    "xml", "data_type", "encoding", "charset", "color", "theme", "style", "class",
]

# =====================================================================
# DOM-XSS leads (client-side): a tainted SOURCE flowing toward a dangerous
# SINK in the same script = manual DOM-XSS lead worth confirming. Heuristic
# co-occurrence only — reported as a lead, never auto-confirmed.
# =====================================================================
DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.url", "document.documenturi", "document.referrer", "window.name",
    "document.cookie", "localstorage", "sessionstorage",
    "urlsearchparams", "location[", "postmessage",
]
DOM_SINKS = [
    "innerhtml", "outerhtml", "document.write", "document.writeln",
    "insertadjacenthtml", "eval(", "settimeout(", "setinterval(",
    "function(", "$(", ".html(", ".append(", ".after(", ".before(",
    ".replacewith(", ".add(", "jquery.globaleval", "window.location",
    "location.assign", "location.replace", "execscript", "createcontextualfragment",
]

# OpenAPI / Swagger spec locations (JSON preferred; a couple of YAML).
OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/api-docs.json", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/api/swagger.json", "/api/openapi.json",
    "/api/v1/openapi.json", "/api/v1/swagger.json", "/openapi/v3",
    "/.well-known/openapi.json", "/docs/openapi.json", "/redoc/openapi.json",
    "/swagger-ui/swagger.json", "/swagger.yaml", "/openapi.yaml",
    "/api/docs", "/swagger-resources",
]

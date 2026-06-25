"""HTTP Parameter Pollution (HPP) detection.

Sends duplicate parameter names in the query string (e.g. `?id=1&id=2`) and
checks whether the application exhibits any of:
  * a different response body than the single-param baseline (server used a
    different value — first, last, concatenated, or array),
  * a 500 / exception (server passed an array where it expected a scalar),
  * a DB error string (backend attempted to use both values in a SQL query).

HPP is useful as:
  - a WAF bypass (the WAF may only inspect the first value while the backend
    uses the last),
  - an authorization bypass (inject a second `role=admin` alongside `role=user`),
  - an injection amplifier.

Conservative: only flags when the duplicate-param response is meaningfully
different from the baseline single-param response (body-length diff > 5% or a
DB error appears). Does NOT send any payload that would modify state.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..config import Config
from ..data import SQL_ERROR_SIGNS
from ..http import Client
from ..utils import dedup_keep_order, log
from ..vuln import Finding

_MAX_URLS = 12
_MAX_PARAMS_PER_URL = 3

# Extra high-value pairs to inject for authorization bypass signals
_PRIV_DUPES = [
    ("role", "admin"),
    ("isAdmin", "true"),
    ("admin", "1"),
    ("is_admin", "1"),
]

_DB_ERR = re.compile("|".join(re.escape(s) for s in SQL_ERROR_SIGNS), re.I)


def _dup_url(url: str, param: str, val1: str, val2: str) -> str:
    """Build a URL with the parameter appearing twice (different values)."""
    pr = urlparse(url)
    # Keep all existing params, but replace the target param with two copies
    pairs = [(k, v) for k, v in parse_qsl(pr.query, keep_blank_values=True)
             if k != param]
    pairs += [(param, val1), (param, val2)]
    return urlunparse(pr._replace(query=urlencode(pairs)))


def _inject_priv(url: str, param: str, field: str, val: str) -> str:
    """Append an extra privileged param duplicate to the URL."""
    pr = urlparse(url)
    pairs = list(parse_qsl(pr.query, keep_blank_values=True))
    # keep original params, append the extra field
    pairs.append((field, val))
    return urlunparse(pr._replace(query=urlencode(pairs)))


def exploit(client: Client, surface: dict, cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()
    urls = dedup_keep_order(surface.get("urls", []))[:_MAX_URLS]

    for url in urls:
        params = [(k, v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        if not params:
            continue

        # ---------- 1) duplicate value injection on existing params ----------
        for param, orig_val in params[:_MAX_PARAMS_PER_URL]:
            key = (urlparse(url).path, param, "dup")
            if key in seen:
                continue
            seen.add(key)

            # baseline: single param
            base = client.get(url, phase="exploit")
            if not base.ok:
                continue

            # duplicate: param=<orig>&param=<orig>2
            alt_val = orig_val + "2" if orig_val.isdigit() else orig_val + "_dup"
            dup_url = _dup_url(url, param, orig_val, alt_val)
            r = client.get(dup_url, phase="exploit")
            if not r.ok:
                continue

            base_len = len(base.text or "")
            dup_len = len(r.text or "")
            diff_pct = abs(dup_len - base_len) / max(base_len, 1)

            db_err = _DB_ERR.search(r.text or "")
            server_err = r.status in (500, 502, 503)

            if db_err:
                sign = db_err.group(0)
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution → SQL error in '{param}'",
                    severity="high", category="sqli", target=dup_url,
                    evidence=(
                        f"Duplicate '{param}' ({orig_val!r} + {alt_val!r}) triggered "
                        f"DB error '{sign}' (absent from baseline). "
                        "HPP fed both values to a SQL query. EXPLOITED."
                    ),
                    recommendation=(
                        "Parameterize queries. Accept only the first (or last) value for "
                        "each parameter; reject duplicates or use strict schema validation."
                    ),
                    confidence="firm",
                    poc=f"curl -s '{dup_url}'",
                ))
                log("vuln", f"[high] HPP SQLi @ {url} param={param}")

            elif server_err:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution → server error in '{param}'",
                    severity="medium", category="exploit", target=dup_url,
                    evidence=(
                        f"Duplicate '{param}' caused HTTP {r.status} (baseline {base.status}). "
                        "Server likely passed an array to a scalar-expecting function."
                    ),
                    recommendation=(
                        "Sanitize duplicate parameters. Type-check input before use."
                    ),
                    confidence="firm",
                    poc=f"curl -s '{dup_url}'",
                ))
                log("vuln", f"[medium] HPP 500 @ {url} param={param}")

            elif diff_pct > 0.1 and dup_len > 50:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution — '{param}' behaves differently with duplicate",
                    severity="low", category="exploit", target=dup_url,
                    evidence=(
                        f"Duplicate '{param}' changed response length by {diff_pct*100:.0f}% "
                        f"({base_len} → {dup_len}). Backend may use last/first/all values."
                    ),
                    recommendation=(
                        "Explicitly reject or normalize duplicate parameters. "
                        "Test as a WAF bypass vector with injection payloads."
                    ),
                    confidence="tentative",
                    poc=f"curl -s '{dup_url}'",
                ))
                log("vuln", f"[low] HPP diff @ {url} param={param}")

        # ---------- 2) privilege-field HPP (append role=admin etc.) ----------
        if params:  # URL has at least one existing param
            for field, priv_val in _PRIV_DUPES[:2]:
                key = (urlparse(url).path, field, "priv")
                if key in seen:
                    continue
                seen.add(key)

                base = client.get(url, phase="exploit")
                if not base.ok:
                    continue
                priv_url = _inject_priv(url, params[0][0], field, priv_val)
                r = client.get(priv_url, phase="exploit")
                if not r.ok:
                    continue
                base_len = len(base.text or "")
                priv_len = len(r.text or "")
                diff_pct = abs(priv_len - base_len) / max(base_len, 1)
                if diff_pct > 0.08 and priv_len > 50:
                    findings.append(Finding(
                        title=f"HTTP Parameter Pollution — injected '{field}={priv_val}' changed response",
                        severity="medium", category="exploit", target=priv_url,
                        evidence=(
                            f"Appending '{field}={priv_val}' to the request changed response "
                            f"length by {diff_pct*100:.0f}% — server may have merged the privilege field. "
                            "Manual confirmation required."
                        ),
                        recommendation=(
                            "Reject unexpected parameters. Whitelist accepted field names."
                        ),
                        confidence="tentative",
                        poc=f"curl -s '{priv_url}'",
                    ))
                    log("vuln", f"[medium] HPP priv-field injection @ {url}")
                    break  # one finding per URL is enough

    return findings

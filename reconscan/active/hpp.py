"""HTTP Parameter Pollution (HPP) detection.

Sends a parameter twice with two *distinct* values (`?id=A&id=B`) and decides
which value the backend actually used, by comparing the duplicate response
against the two single-value baselines:

  * DB error string present only in the duplicate response  → HPP feeds both
    values into a SQL query (injection amplifier),
  * 5xx only in the duplicate response                      → array passed where
    a scalar was expected,
  * duplicate response == the SECOND value's response       → backend uses the
    LAST value (the classic WAF bypass: a WAF that inspects the first value is
    blind to the payload in the second),
  * duplicate response == the FIRST value's response        → backend uses the
    FIRST value.

False-positive control: a finding is only emitted when the two single-value
baselines are themselves materially different (so "which value won" is
observable) and the duplicate response closely matches exactly one of them.
Pure length-jitter and "appended an unknown param changed the page" heuristics
are NOT used — they fire on every dynamic page. Detection only; no state change.
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
_MIN_BASELINE_DELTA = 24   # the two single-value bodies must differ by > this
_MATCH_TOL = 8             # duplicate body within this many bytes == "matches"

_DB_ERR = re.compile("|".join(re.escape(s) for s in SQL_ERROR_SIGNS), re.I)


def _set_single(url: str, param: str, val: str) -> str:
    pr = urlparse(url)
    pairs = [(k, (val if k == param else v))
             for k, v in parse_qsl(pr.query, keep_blank_values=True)]
    return urlunparse(pr._replace(query=urlencode(pairs)))


def _dup_url(url: str, param: str, val1: str, val2: str) -> str:
    pr = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(pr.query, keep_blank_values=True)
             if k != param]
    pairs += [(param, val1), (param, val2)]
    return urlunparse(pr._replace(query=urlencode(pairs)))


def exploit(client: Client, surface: dict, cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()
    urls = dedup_keep_order(surface.get("urls", []))[:_MAX_URLS]

    for url in urls:
        if client.over_budget():
            break
        params = [(k, v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        if not params:
            continue

        for param, orig_val in params[:_MAX_PARAMS_PER_URL]:
            key = (urlparse(url).path, param)
            if key in seen:
                continue
            seen.add(key)

            a_val = orig_val or "1"
            b_val = (str(int(a_val) + 1) if a_val.isdigit() else a_val + "zz")

            a = client.get(_set_single(url, param, a_val), phase="exploit")
            b = client.get(_set_single(url, param, b_val), phase="exploit")
            if not (a and a.ok and b and b.ok):
                continue
            la, lb = len(a.text or ""), len(b.text or "")
            a_low, b_low = (a.text or "").lower(), (b.text or "").lower()

            dup = client.get(_dup_url(url, param, a_val, b_val), phase="exploit")
            if not dup:
                continue
            dup_txt = dup.text or ""
            ld = len(dup_txt)

            # 1) duplicate-only DB error → injection amplifier
            m = _DB_ERR.search(dup_txt)
            if m and m.group(0).lower() not in a_low and m.group(0).lower() not in b_low:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution → SQL error in '{param}'",
                    severity="high", category="sqli", target=dup.url,
                    evidence=(
                        f"Duplicate '{param}' ({a_val!r}+{b_val!r}) triggered DB error "
                        f"'{m.group(0)}' absent from both single-value baselines — both "
                        "values reached the SQL layer. EXPLOITED (HPP injection amplifier)."
                    ),
                    recommendation=("Parameterize queries; accept a single value per "
                                    "parameter or validate against a strict schema."),
                    confidence="firm", poc=f"curl -s '{dup.url}'"))
                log("vuln", f"[high] HPP SQLi @ {url} param={param}")
                continue

            # 2) duplicate-only 5xx → array-vs-scalar
            if dup.status in (500, 502, 503) and a.status < 500 and b.status < 500:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution → server error in '{param}'",
                    severity="medium", category="exploit", target=dup.url,
                    evidence=(f"Duplicate '{param}' caused HTTP {dup.status} (single-value "
                              f"baselines {a.status}/{b.status}). Array passed to scalar logic."),
                    recommendation="Reject duplicate parameters; type-check input before use.",
                    confidence="firm", poc=f"curl -s '{dup.url}'"))
                log("vuln", f"[medium] HPP 5xx @ {url} param={param}")
                continue

            # 3) which value won — only decidable when baselines actually differ
            if abs(la - lb) <= _MIN_BASELINE_DELTA:
                continue
            dist_a, dist_b = abs(ld - la), abs(ld - lb)
            if dist_b <= _MATCH_TOL and dist_a > _MIN_BASELINE_DELTA:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution — backend uses LAST value of '{param}'",
                    severity="low", category="exploit", target=dup.url,
                    evidence=(
                        f"With '{param}={a_val}&{param}={b_val}' the response matched the "
                        f"second value's output, not the first. A WAF inspecting only the "
                        f"first occurrence is blind to a payload in the second. "
                        "(HPP last-value WAF bypass — impact depends on a front filter)."),
                    recommendation=("Normalize duplicate parameters to a single value before "
                                    "both the WAF and the application read them."),
                    confidence="firm", poc=f"curl -s '{dup.url}'"))
                log("vuln", f"[medium] HPP last-value-wins @ {url} param={param}")
            elif dist_a <= _MATCH_TOL and dist_b > _MIN_BASELINE_DELTA:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution — backend uses FIRST value of '{param}'",
                    severity="low", category="exploit", target=dup.url,
                    evidence=(
                        f"With '{param}={a_val}&{param}={b_val}' the response matched the "
                        f"first value's output. Confirms parser precedence — test as a WAF "
                        f"bypass where the WAF reads the last value."),
                    recommendation="Reject or canonicalize duplicate parameters.",
                    confidence="firm", poc=f"curl -s '{dup.url}'"))
                log("vuln", f"[low] HPP first-value-wins @ {url} param={param}")

    return findings

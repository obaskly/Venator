"""Open-redirect detection (read-only, benign canary).

Injects an external canary (IANA-reserved example.com) into common redirect
parameters and checks whether the app hands it back in a Location header or a
meta/JS refresh. We NEVER follow the redirect — we only observe that the
attacker-controlled host would be honored.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ..config import Config
from ..data import REDIRECT_CANARY, REDIRECT_HOST_MARK, REDIRECT_PARAMS
from ..http import Client
from ..utils import log
from ..vuln import Finding

_META_REFRESH = re.compile(r"""(?:url=|location(?:\.href)?\s*=\s*['"]?)\s*(https?://[^\s'"]+)""", re.I)


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[param] = value
    return urlunparse(parts._replace(query=urlencode(qs)))


def check(client: Client, base_urls: List[str], cfg: Config) -> List[Finding]:
    if not base_urls:
        return []
    log("info", f"open-redirect probe on {len(base_urls)} base URL(s)")
    findings: List[Finding] = []

    for base in base_urls:
        for param in REDIRECT_PARAMS:
            test = _with_param(base, param, REDIRECT_CANARY)
            r = client.get(test, phase="active", allow_redirects=False)
            if not r.ok:
                continue
            loc = r.headers.get("location", "")
            in_location = REDIRECT_HOST_MARK in loc
            refresh_hdr = r.headers.get("refresh", "")
            in_refresh = REDIRECT_HOST_MARK in refresh_hdr
            in_body = False
            if not in_location and not in_refresh and 200 <= r.status < 300:
                m = _META_REFRESH.search(r.text or "")
                in_body = bool(m and REDIRECT_HOST_MARK in (m.group(1) or ""))
            if in_location or in_refresh or in_body:
                where = ("Location header" if in_location else
                         "Refresh header" if in_refresh else "meta/JS refresh")
                findings.append(Finding(
                    title=f"Open redirect via '{param}' parameter",
                    severity="medium", category="redirect", target=test,
                    evidence=f"canary host honored in {where}: "
                             f"{loc or '(body)'} (status {r.status})",
                    recommendation=("Confirm the redirect reaches an external "
                                    "attacker-controlled host, then report. Chain "
                                    "potential: OAuth token theft / phishing. Fix "
                                    "with an allowlist of internal redirect targets."),
                    confidence="firm"))
                log("vuln", f"[medium] open redirect: {param} @ {base}")
                break  # one param is enough per base
    return findings

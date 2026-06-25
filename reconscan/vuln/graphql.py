"""GraphQL discovery + introspection check (read-only).

Locates GraphQL endpoints and tests whether introspection is enabled. An open
introspection schema is a real bug-bounty finding: it hands an attacker the full
API surface (types, queries, mutations). The probe is a single read-only
introspection query — it never runs a mutation.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..data import GRAPHQL_PATHS
from ..http import Client
from ..utils import log
from . import Finding

# Minimal introspection query — read-only.
_Q = "{__schema{queryType{name}}}"


def check(client: Client, base_urls: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    roots = []
    for b in base_urls:
        p = urlparse(b)
        root = f"{p.scheme}://{p.netloc}"
        if root not in roots:
            roots.append(root)

    for root in roots:
        for path in GRAPHQL_PATHS:
            url = root + path
            resp = client.get(url, phase="graphql",
                              extra_headers={"Accept": "application/json"})
            if not resp.ok:
                continue
            # endpoint exists if it responds to GET introspection meaningfully
            probe = client.get(f"{url}?query={_Q}", phase="graphql",
                               extra_headers={"Accept": "application/json"})
            body = (probe.text or "")[:5000].lower()
            if '"__schema"' in body or '"querytype"' in body or '"data":{"__schema"' in body:
                findings.append(Finding(
                    title="GraphQL introspection enabled",
                    severity="medium", category="misconfig", target=url,
                    evidence="introspection query returned a schema "
                             f"(__schema present) at {url}",
                    recommendation=("Map the full schema with a GraphQL client, then "
                                    "hunt authz gaps on queries/mutations. Disable "
                                    "introspection in production if not required."),
                    confidence="firm"))
                log("vuln", f"[medium] GraphQL introspection @ {url}")
                break  # one per root is enough
    return findings

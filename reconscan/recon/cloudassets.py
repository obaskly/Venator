"""Cloud object-storage bucket enumeration — find exposed S3/GCS/Azure/R2/Spaces.

Exposed cloud storage is one of the highest-signal-per-effort findings in modern
bug bounty: a single public bucket can leak source, backups, PII or credentials.
Most hunters never enumerate it.

Method (target-agnostic, name-permutation): derive candidate bucket/account names
from the apex label (``acme`` -> ``acme-prod``, ``acme-backups``, ``acme-assets``…)
and probe each across providers. Confirmation is by the provider's own response:

  * 200 + a listing document (``<ListBucketResult>`` / ``EnumerationResults``)
        -> PUBLIC, listable bucket  (high, confirmed)
  * 403 / AccessDenied                       -> bucket exists but private (info)
  * 404 / NoSuchBucket / NXDOMAIN            -> nothing there

Every probe is a credential-isolated, allowlisted, audited ``client.cloud_request``
(never the target, never the target's session). It reads listings only — it never
downloads object contents and never writes. R2 ``*.r2.dev`` URLs use a random hash
(not name-guessable) so only S3 / GCS / Azure are permutation-probed.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List
from urllib.parse import urlparse

from ..config import Config
from ..http import Client
from ..utils import log
from ..vuln import Finding

# name suffixes/prefixes that commonly distinguish a company's buckets
_SUFFIXES = ["", "-prod", "-production", "-dev", "-development", "-staging",
             "-stage", "-test", "-qa", "-assets", "-static", "-media", "-images",
             "-img", "-uploads", "-files", "-data", "-backup", "-backups", "-bak",
             "-public", "-private", "-cdn", "-content", "-logs", "-www", "-app",
             "-api", "-internal", "-archive", "-store", "-storage"]
_PREFIXES = ["prod-", "dev-", "staging-", "test-", "backup-", "assets-", "static-"]

_LIST_SIGN = re.compile(r"<ListBucketResult|<EnumerationResults|<\?xml[^>]*>\s*<List", re.I)
_PRIVATE_SIGN = re.compile(r"AccessDenied|<Code>AccessDenied|InvalidAccessKeyId|"
                           r"all access to this object has been disabled|"
                           r"AuthorizationPermissionMismatch|PublicAccessNotPermitted", re.I)
# Azure-SPECIFIC existence signals (a generic <Error> would FP on S3/GCS bodies).
# A nonexistent storage account fails DNS, so simply getting an Azure-flavoured
# HTTP response back is the existence signal.
_AZURE_EXISTS = re.compile(r"InvalidQueryParameterValue|AuthenticationFailed|"
                           r"ResourceNotFound|ContainerNotFound|BlobNotFound|"
                           r"The requested URI does not represent", re.I)
_AZURE_CONTAINERS = ["", "public", "files", "data", "backup", "media", "assets"]


def _is_azure(resp) -> bool:
    if not resp.ok or resp.error:
        return False
    if any(k.lower().startswith("x-ms-") for k in (resp.headers or {})):
        return True
    return bool(_AZURE_EXISTS.search(resp.text or ""))


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split(":", 1)[0])
        return True
    except ValueError:
        return False


def _candidates(apex: str, limit: int = 40) -> List[str]:
    host = apex.split(":", 1)[0].strip().lower().rstrip(".")
    if not host or _looks_like_ip(host) or host in ("localhost",):
        return []
    label = host.split(".")[0]
    if len(label) < 3:
        return []
    full = host.replace(".", "-")
    names: List[str] = []
    seen = set()
    for base in (label, full):
        for w in _SUFFIXES:
            n = base + w
            if n not in seen and 3 <= len(n) <= 63:
                seen.add(n); names.append(n)
        for p in _PREFIXES:
            n = p + base
            if n not in seen and 3 <= len(n) <= 63:
                seen.add(n); names.append(n)
    return names[:limit]


def _bucket_finding(provider: str, name: str, url: str, state: str) -> Finding:
    if state == "public":
        return Finding(
            title=f"Public {provider} bucket lists objects",
            severity="high", category="exploit", target=url,
            evidence=(f"The {provider} bucket '{name}' returned a public object listing "
                      f"({url}) without authentication — anyone can enumerate (and likely "
                      "read) its contents. Buckets named after the target routinely hold "
                      "source, backups, or PII. EXPLOITED (read-only listing)."),
            recommendation=("Make the bucket private, enable Block Public Access / uniform "
                            "bucket-level access, and audit what was exposed."),
            confidence="confirmed",
            poc=f"curl -s '{url}'")
    return Finding(
        title=f"{provider} bucket exists (private) — name matches target",
        severity="info", category="recon", target=url,
        evidence=(f"A {provider} bucket/account '{name}' (derived from the target name) "
                  f"exists but denied anonymous access ({url}). Worth checking for weak "
                  "ACLs, predictable object keys, or write access during an engagement."),
        recommendation="Confirm ownership; test object-level ACLs and bucket policy.",
        confidence="tentative",
        poc=f"curl -s '{url}'")


def _classify(resp) -> str:
    """'public' | 'private' | 'none' for an S3/GCS-style response."""
    if not resp.ok or resp.error:
        return "none"
    if resp.status == 200 and _LIST_SIGN.search(resp.text or ""):
        return "public"
    if resp.status in (401, 403) or _PRIVATE_SIGN.search(resp.text or ""):
        return "private"
    return "none"


def _probe_name(client: Client, name: str) -> List[Finding]:
    out: List[Finding] = []
    # --- AWS S3 (virtual-host style) ---
    r = client.cloud_request("GET", f"https://{name}.s3.amazonaws.com/")
    st = _classify(r)
    if st != "none":
        out.append(_bucket_finding("S3", name, f"https://{name}.s3.amazonaws.com/", st))
    # --- Google Cloud Storage (path style) ---
    r = client.cloud_request("GET", f"https://storage.googleapis.com/{name}/")
    st = _classify(r)
    if st != "none":
        out.append(_bucket_finding("GCS", name,
                                   f"https://storage.googleapis.com/{name}/", st))
    # --- Azure Blob (account existence, then a few common public containers) ---
    acct = client.cloud_request("GET", f"https://{name}.blob.core.windows.net/")
    if _is_azure(acct):
        public_hit = False
        for cont in _AZURE_CONTAINERS:
            if client.over_budget():
                break
            cu = (f"https://{name}.blob.core.windows.net/"
                  f"{cont}?restype=container&comp=list")
            cr = client.cloud_request("GET", cu)
            if cr.ok and cr.status == 200 and _LIST_SIGN.search(cr.text or ""):
                out.append(_bucket_finding("Azure Blob", f"{name}/{cont or '$root'}",
                                           cu, "public"))
                public_hit = True
                break
        if not public_hit:
            out.append(_bucket_finding("Azure Blob", name,
                                       f"https://{name}.blob.core.windows.net/", "private"))
    return out


def check(client: Client, cfg: Config) -> List[Finding]:
    names = _candidates(cfg.target)
    if not names:
        return []
    log("step", f"Cloud bucket enumeration ({len(names)} candidate name(s), "
                "S3/GCS/Azure)")
    findings: List[Finding] = []
    for name in names:
        if client.over_budget():
            break
        for f in _probe_name(client, name):
            findings.append(f)
            lvl = "vuln" if f.severity != "info" else "info"
            log(lvl, f"[{f.severity}] {f.title} @ {f.target}")
    pub = sum(1 for f in findings if f.severity == "high")
    log("ok", f"cloud assets: {len(findings)} candidate(s), {pub} public bucket(s)")
    return findings

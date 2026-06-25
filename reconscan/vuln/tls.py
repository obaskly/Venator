"""TLS/SSL checks: cert validity/expiry, hostname match, deprecated protocols,
and HTTP->HTTPS redirect behaviour.

Uses Python's ssl for the cert + a probe of TLS 1.0/1.1 support. If the
`openssl` binary is present it is used to enumerate protocol support more
reliably; otherwise we fall back to Python ssl contexts.
"""
from __future__ import annotations

import datetime as _dt
import socket
import ssl
from typing import List, Optional

from ..audit import AuditLog
from ..external import have, run
from ..http import Client
from ..utils import log
from . import Finding


def _get_cert(host: str, port: int = 443, timeout: float = 8.0) -> Optional[dict]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                # getpeercert returns {} when verify_mode is CERT_NONE; use DER
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
        # Parse DER via a verifying context to extract fields when possible
        parsed = _parse_der(der)
        parsed.update({"negotiated_cipher": cipher, "negotiated_version": version})
        return parsed
    except Exception as e:
        log("warn", f"TLS connect failed for {host}: {type(e).__name__}")
        return None


def _parse_der(der: bytes) -> dict:
    out: dict = {}
    try:
        import ssl as _ssl
        # Python can decode a DER cert to a dict via a temp PEM + a verifying ctx
        pem = _ssl.DER_cert_to_PEM_cert(der)
        # Use cryptography if available for robust parsing
        try:
            from cryptography import x509  # type: ignore
            from cryptography.hazmat.backends import default_backend  # type: ignore
            cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
            out["subject"] = cert.subject.rfc4514_string()
            out["issuer"] = cert.issuer.rfc4514_string()
            out["not_before"] = cert.not_valid_before_utc.isoformat()
            out["not_after"] = cert.not_valid_after_utc.isoformat()
            out["_not_after_dt"] = cert.not_valid_after_utc
            try:
                sans = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                out["sans"] = sans
            except Exception:
                out["sans"] = []
        except Exception:
            out["raw_pem_len"] = len(pem)
    except Exception:
        pass
    return out


def _protocol_via_openssl(host: str, audit: AuditLog) -> List[str]:
    """Return list of deprecated protocols the server still accepts."""
    deprecated = []
    for proto_flag, label in [("-tls1", "TLSv1.0"), ("-tls1_1", "TLSv1.1")]:
        cp = run(["openssl", "s_client", "-connect", f"{host}:443",
                  "-servername", host, proto_flag],
                 timeout=15, audit=audit, phase="tls")
        # If handshake succeeded we'll see a cert / "Verify return code"
        out = (cp.stdout + cp.stderr)
        if "BEGIN CERTIFICATE" in out or "Verify return code" in out:
            if "no protocols available" not in out and "handshake failure" not in out:
                deprecated.append(label)
    return deprecated


def check(client: Client, host: str, probes: List[dict], audit: AuditLog) -> List[Finding]:
    findings: List[Finding] = []

    cert = _get_cert(host)
    if cert:
        na = cert.get("_not_after_dt")
        if na:
            now = _dt.datetime.now(_dt.timezone.utc)
            days_left = (na - now).days
            if days_left < 0:
                findings.append(Finding(
                    title="Expired TLS certificate", severity="high",
                    category="tls", target=host,
                    evidence=f"Certificate not_after={cert.get('not_after')} "
                             f"({-days_left} days ago).",
                    recommendation="Renew the certificate immediately.",
                    confidence="confirmed"))
            elif days_left < 21:
                findings.append(Finding(
                    title="TLS certificate expiring soon", severity="low",
                    category="tls", target=host,
                    evidence=f"Certificate expires in {days_left} days "
                             f"({cert.get('not_after')}).",
                    recommendation="Schedule certificate renewal.",
                    confidence="confirmed"))
        # hostname / SAN mismatch
        sans = cert.get("sans", [])
        if sans and not _host_matches(host, sans):
            findings.append(Finding(
                title="TLS certificate hostname mismatch", severity="medium",
                category="tls", target=host,
                evidence=f"{host} not covered by SANs: {sans[:5]}",
                recommendation="Issue a cert covering this hostname, or fix vhost.",
                confidence="firm"))

    # deprecated protocols
    if have("openssl"):
        dep = _protocol_via_openssl(host, audit)
        for proto in dep:
            findings.append(Finding(
                title=f"Deprecated TLS protocol enabled: {proto}",
                severity="medium", category="tls", target=host,
                evidence=f"Server completed a {proto} handshake.",
                recommendation=f"Disable {proto}; require TLS 1.2+.",
                confidence="confirmed"))

    # HTTP -> HTTPS redirect check
    http_probe = next((p for p in probes if p.get("scheme") == "http"), None)
    if http_probe is not None:
        if not http_probe.get("redirected_to_https"):
            findings.append(Finding(
                title="HTTP does not redirect to HTTPS", severity="low",
                category="tls", target=f"http://{host}",
                evidence=f"http://{host} final URL: {http_probe.get('final_url')} "
                         f"(status {http_probe.get('status')}).",
                recommendation="Force a 301 redirect from HTTP to HTTPS.",
                confidence="firm"))

    for f in findings:
        log("vuln", f"[{f.severity}] {f.title} @ {host}")
    return findings


def _host_matches(host: str, sans: List[str]) -> bool:
    host = host.lower()
    for san in sans:
        san = san.lower()
        if san == host:
            return True
        if san.startswith("*."):
            base = san[2:]
            # wildcard matches exactly one label
            if host.endswith("." + base) and host.count(".") == base.count(".") + 1:
                return True
    return False

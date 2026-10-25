"""TLS checks: protocol version, certificate trust, and expiry."""

from __future__ import annotations

import socket
import ssl
import time
from typing import List, Optional, Tuple

from ..http import TLSInfo
from ..models import Context, Finding, Severity

WEAK_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.0"}
EXPIRY_WARNING_DAYS = 30.0


def _name(cert: dict, field: str) -> str:
    parts = []
    for entry in cert.get(field, []):
        for key, value in entry:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _wrap(host: str, port: int, timeout: float, verify: bool) -> Tuple[ssl.SSLSocket, dict]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        wrapped = context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise
    return wrapped, wrapped.getpeercert() or {}


def inspect_tls(host: str, port: int = 443, timeout: float = 10.0) -> TLSInfo:
    """Return what the handshake reveals, without ever aborting the scan."""
    try:
        wrapped, cert = _wrap(host, port, timeout, verify=True)
        with wrapped:
            return TLSInfo(
                version=wrapped.version() or "",
                cipher=(wrapped.cipher() or ("", "", 0))[0],
                subject=_name(cert, "subject"),
                issuer=_name(cert, "issuer"),
                not_after=cert.get("notAfter", ""),
                trusted=True,
            )
    except ssl.SSLCertVerificationError as exc:
        # Still gather the configuration so the report can say *why* it is untrusted.
        try:
            wrapped, cert = _wrap(host, port, timeout, verify=False)
            with wrapped:
                info = TLSInfo(
                    version=wrapped.version() or "",
                    cipher=(wrapped.cipher() or ("", "", 0))[0],
                    subject=_name(cert, "subject"),
                    issuer=_name(cert, "issuer"),
                    not_after=cert.get("notAfter", ""),
                    trusted=False,
                )
        except (ssl.SSLError, OSError) as inner:
            return TLSInfo(version="", cipher="", trusted=False, error=str(inner))
        info.error = str(exc)
        return info


def _days_until(not_after: str) -> Optional[float]:
    if not not_after:
        return None
    try:
        expiry = ssl.cert_time_to_seconds(not_after)
    except ValueError:
        return None
    return (expiry - time.time()) / 86400.0


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []

    if ctx.target.scheme != "https":
        findings.append(
            Finding(
                check_id="TLS-001",
                title="Site served over plain HTTP",
                severity=Severity.HIGH,
                detail=(
                    "Everything on this connection - credentials, session cookies, page content - is "
                    "readable and modifiable by anyone positioned on the path."
                ),
                evidence=f"Target scheme is {ctx.target.scheme}.",
                remediation=(
                    "Serve the site over HTTPS only, redirect port 80 to 443, and add HSTS once the "
                    "redirect has been verified."
                ),
                reference="OWASP Transport Layer Security Cheat Sheet",
            )
        )
        return findings

    info = ctx.tls
    if info is None:
        return findings

    if info.version in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                check_id="TLS-010",
                title=f"Obsolete TLS version negotiated ({info.version})",
                severity=Severity.HIGH,
                detail="TLS 1.0/1.1 and SSLv3 have known weaknesses and are deprecated by every major browser.",
                evidence=f"Negotiated {info.version} with cipher {info.cipher}.",
                remediation="Require TLS 1.2 or newer; TLS 1.3 where clients allow it.",
                reference="OWASP Transport Layer Security Cheat Sheet",
            )
        )

    if not info.trusted:
        findings.append(
            Finding(
                check_id="TLS-020",
                title="Certificate is not trusted by a public CA",
                severity=Severity.MEDIUM,
                detail=(
                    "A self-signed or otherwise untrusted certificate trains users to click through "
                    "warnings, which is exactly the habit a man-in-the-middle attack depends on. In a "
                    "lab this is expected; in production it is a defect."
                ),
                evidence=info.error or f"Issuer: {info.issuer or 'unknown'}",
                remediation="Install a certificate from a trusted CA (Let's Encrypt is free) and renew automatically.",
                reference="OWASP Transport Layer Security Cheat Sheet",
            )
        )

    days = _days_until(info.not_after)
    if days is not None:
        if days < 0:
            findings.append(
                Finding(
                    check_id="TLS-030",
                    title="Certificate has expired",
                    severity=Severity.HIGH,
                    detail="Browsers block or warn on an expired certificate, so users cannot reach the site safely.",
                    evidence=f"Expired {abs(days):.0f} days ago (notAfter: {info.not_after}).",
                    remediation="Renew immediately and automate renewal so it cannot lapse again.",
                    reference="OWASP Transport Layer Security Cheat Sheet",
                )
            )
        elif days < EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    check_id="TLS-031",
                    title="Certificate expires soon",
                    severity=Severity.MEDIUM,
                    detail="A lapse in the next few weeks would take the site down for every user.",
                    evidence=f"{days:.0f} days remaining (notAfter: {info.not_after}).",
                    remediation="Renew now, then automate renewal and add expiry monitoring.",
                    reference="OWASP Transport Layer Security Cheat Sheet",
                )
            )

    return findings

"""Information disclosure: banners, verbose errors, directory listing, exposed files.

Every probe here is a single ordinary GET - no payloads, no fuzzing, no writes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List

from ..http import Response, ScanError
from ..models import Context, Finding, Severity

ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,}=", re.MULTILINE)
VERSION_PATTERN = re.compile(r"\d+\.\d+")
TRACEBACK_MARKERS = (
    "Traceback (most recent call last)",
    "SQLSTATE[",
    "Warning: mysql_",
    "Notice: Undefined variable",
    "at java.lang.",
    "System.Data.SqlClient.SqlException",
)


@dataclass(frozen=True)
class Probe:
    check_id: str
    path: str
    title: str
    severity: Severity
    detail: str
    remediation: str
    reference: str
    detector: Callable[[Response], bool]


def snippet(response: Response, limit: int = 60) -> str:
    """Quote what actually matched, so the report shows evidence rather than a verdict."""
    if response.body[:4] in (b"PK\x03\x04", b"\x00\x00\x00\x01"):
        return response.body[:12].hex(" ")
    text = " ".join(response.text.split())
    if not text:
        return "(empty body)"
    return text[:limit] + ("..." if len(text) > limit else "")


def _looks_like_git(response: Response) -> bool:
    return response.status == 200 and response.text[:64].lstrip().startswith("ref:")


def _looks_like_env(response: Response) -> bool:
    return response.status == 200 and bool(ENV_PATTERN.search(response.text[:8000]))


def _contains(marker: str) -> Callable[[Response], bool]:
    return lambda response: response.status == 200 and marker in response.text


def _binary(prefix: bytes) -> Callable[[Response], bool]:
    return lambda response: response.status == 200 and response.body.startswith(prefix)


PROBES: List[Probe] = [
    Probe(
        check_id="DISC-101",
        path="/.git/HEAD",
        title="Exposed Git repository",
        severity=Severity.HIGH,
        detail=(
            "The repository metadata is readable, which usually allows the full source history - "
            "including credentials and secrets that were deleted from the current code - to be recovered."
        ),
        remediation=(
            "Block dotfiles at the web server, remove the .git directory from the document root, "
            "and rotate any secret that was ever committed."
        ),
        reference="OWASP WSTG: Review Webpage Content for Information Leakage",
        detector=_looks_like_git,
    ),
    Probe(
        check_id="DISC-102",
        path="/.env",
        title="Exposed environment file (.env)",
        severity=Severity.HIGH,
        detail=(
            "Environment files normally hold database passwords, API keys, and signing secrets; "
            "readable from the web they hand an attacker the keys to the application."
        ),
        remediation=(
            "Move .env outside the document root, deny the path at the server, and rotate every "
            "credential it contained."
        ),
        reference="OWASP WSTG: Review Webpage Content for Information Leakage",
        detector=_looks_like_env,
    ),
    Probe(
        check_id="DISC-103",
        path="/server-status",
        title="Apache server-status page exposed",
        severity=Severity.MEDIUM,
        detail=(
            "The status page lists active requests and client addresses, which reveals internal URLs, "
            "traffic patterns, and sometimes other users' activity."
        ),
        remediation="Restrict /server-status to localhost, or disable mod_status in production.",
        reference="OWASP WSTG: Review Webpage Content for Information Leakage",
        detector=_contains("Apache Server Status"),
    ),
    Probe(
        check_id="DISC-104",
        path="/phpinfo.php",
        title="phpinfo() page exposed",
        severity=Severity.MEDIUM,
        detail=(
            "phpinfo() prints the full PHP configuration, loaded extensions, document paths, and "
            "sometimes environment values - a detailed map of the server for an attacker."
        ),
        remediation="Delete the file; phpinfo() is a development aid, never a production page.",
        reference="OWASP WSTG: Review Webpage Content for Information Leakage",
        detector=_contains("PHP Version"),
    ),
    Probe(
        check_id="DISC-105",
        path="/.DS_Store",
        title="macOS .DS_Store file exposed",
        severity=Severity.LOW,
        detail=(
            "The Finder metadata file lists directory contents, letting an attacker enumerate files "
            "that may not be linked anywhere on the site."
        ),
        remediation="Block dotfiles at the web server and deploy from a clean export, not a desktop folder.",
        reference="OWASP WSTG: Review Webpage Content for Information Leakage",
        detector=_binary(b"\x00\x00\x00\x01Bud1"),
    ),
    Probe(
        check_id="DISC-106",
        path="/backup.zip",
        title="Backup archive reachable",
        severity=Severity.HIGH,
        detail=(
            "A downloadable backup typically contains source code, configuration, and database dumps - "
            "often the fastest route from a web request to full compromise."
        ),
        remediation="Store backups outside the web root and require authentication for any download route.",
        reference="OWASP WSTG: Review Webpage Content for Information Leakage",
        detector=_binary(b"PK\x03\x04"),
    ),
]


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    response = ctx.response

    # --- Banner disclosure ------------------------------------------------
    server = response.get("Server", "")
    powered_by = response.get("X-Powered-By", "")
    banners = []
    if server and VERSION_PATTERN.search(server):
        banners.append(f"Server: {server}")
    if powered_by:
        banners.append(f"X-Powered-By: {powered_by}")
    if banners:
        findings.append(
            Finding(
                check_id="DISC-001",
                title="Server software and version disclosed",
                severity=Severity.LOW,
                detail=(
                    "Not exploitable on its own, but it tells an attacker which known vulnerabilities "
                    "to try first and saves them the reconnaissance."
                ),
                evidence="; ".join(banners),
                remediation="Suppress version strings (ServerTokens Prod, expose_php Off) or front the app with a proxy that normalises headers.",
                reference="OWASP WSTG: Fingerprint Web Server",
            )
        )

    # --- Verbose errors ---------------------------------------------------
    if response.status >= 500:
        hit = next((marker for marker in TRACEBACK_MARKERS if marker in response.text), None)
        if hit:
            findings.append(
                Finding(
                    check_id="DISC-010",
                    title="Verbose error output on a server error",
                    severity=Severity.MEDIUM,
                    detail=(
                        "Stack traces and database errors reveal file paths, library versions, and "
                        "query structure - the sort of detail that turns a blind bug into a precise exploit."
                    ),
                    evidence=f"HTTP {response.status} response contained '{hit}'.",
                    remediation="Return a generic error page, log the detail server-side, and disable debug mode in production.",
                    reference="OWASP WSTG: Review Webpage Content for Information Leakage",
                )
            )

    # --- Directory listing ------------------------------------------------
    if response.status == 200 and re.search(r"<title>\s*Index of /", response.text, re.IGNORECASE):
        findings.append(
            Finding(
                check_id="DISC-020",
                title="Directory listing enabled",
                severity=Severity.MEDIUM,
                detail=(
                    "The server prints an index of the directory, which exposes files that were never "
                    "meant to be browsed - drafts, exports, and old backups."
                ),
                evidence="Root response body contains an 'Index of /' title.",
                remediation="Disable auto-indexing (Options -Indexes in Apache, autoindex off in nginx).",
                reference="OWASP WSTG: Directory Traversal and File Include",
            )
        )

    # --- Exposed paths ----------------------------------------------------
    base = ctx.target.base
    for probe in PROBES:
        url = base + probe.path
        if probe.path in ctx.fetched:
            candidate = ctx.fetched[probe.path]
        else:
            try:
                candidate = ctx.session.fetch(url)
            except ScanError:
                continue
            ctx.fetched[probe.path] = candidate
        try:
            matched = probe.detector(candidate)
        except Exception:  # a detector must never break the scan
            matched = False
        if matched:
            findings.append(
                Finding(
                    check_id=probe.check_id,
                    title=probe.title,
                    severity=probe.severity,
                    detail=probe.detail,
                    evidence=f"GET {probe.path} -> HTTP {candidate.status}, body: {snippet(candidate)!r}",
                    remediation=probe.remediation,
                    reference=probe.reference,
                )
            )

    return findings

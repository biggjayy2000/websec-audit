"""Orchestration: resolve scope, gather evidence once, run every check, collect findings."""

from __future__ import annotations

import datetime as _dt
import time
from typing import Optional
from urllib.parse import urlsplit

from .checks import ALL_CHECKS
from .checks.tls import inspect_tls
from .http import ScanError, Session
from .models import Context, ScanResult, Target
from .scope import check_target

DEFAULT_TIMEOUT = 10.0
DEFAULT_DELAY = 0.15


def parse_target(raw: str) -> Target:
    """Accept 'example.com', 'http://example.com:8080/app' and friends."""
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate
    parts = urlsplit(candidate)
    if not parts.hostname:
        raise ValueError(f"Could not read a hostname from '{raw}'")
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{scheme}' (only http and https)")
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    url = f"{scheme}://{parts.hostname}:{port}{path}" if parts.port else f"{scheme}://{parts.hostname}{path}"
    return Target(url=url, host=parts.hostname, scheme=scheme, port=port)


def scan(
    raw_target: str,
    timeout: float = DEFAULT_TIMEOUT,
    delay: float = DEFAULT_DELAY,
    allow_private: bool = False,
    authorized: bool = False,
) -> ScanResult:
    target = parse_target(raw_target)

    # Scope is enforced before a single packet is sent.
    scope_reason = check_target(target.host, allow_private=allow_private, authorized=authorized)

    started_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    started = time.monotonic()
    session = Session(timeout=timeout, delay=delay)
    errors: list[str] = []
    findings = []

    tls_info = None
    if target.scheme == "https":
        try:
            tls_info = inspect_tls(target.host, target.port, timeout)
        except Exception as exc:  # never abort a scan because TLS was odd
            errors.append(f"TLS inspection failed: {exc}")

    try:
        response = session.fetch(target.url)
    except ScanError as exc:
        return ScanResult(
            target=target.url,
            started=started_at,
            duration=time.monotonic() - started,
            request_count=session.requests,
            findings=[],
            errors=[f"{scope_reason}; could not fetch target: {exc}"],
        )

    ctx = Context(target=target, response=response, session=session, tls=tls_info)

    for label, check in ALL_CHECKS:
        try:
            findings.extend(check(ctx))
        except Exception as exc:  # one broken check must not lose the others
            errors.append(f"{label} check failed: {exc}")

    return ScanResult(
        target=target.url,
        started=started_at,
        duration=time.monotonic() - started,
        request_count=session.requests,
        findings=findings,
        errors=errors,
    )

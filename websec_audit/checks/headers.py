"""Response-header checks: the cheapest high-signal part of any web assessment."""

from __future__ import annotations

from typing import List

from ..models import Context, Finding, Severity

MIN_HSTS_MAX_AGE = 15552000  # 180 days


def _hsts_max_age(value: str) -> int:
    for part in value.split(";"):
        key, _, raw = part.strip().partition("=")
        if key.strip().lower() == "max-age":
            try:
                return int(raw.strip().strip('"'))
            except ValueError:
                return 0
    return 0


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    response = ctx.response
    https = ctx.target.scheme == "https"

    # --- HSTS -------------------------------------------------------------
    hsts = response.get("Strict-Transport-Security")
    if https:
        if not hsts:
            findings.append(
                Finding(
                    check_id="HDR-001",
                    title="Strict-Transport-Security header missing",
                    severity=Severity.MEDIUM,
                    detail=(
                        "Without HSTS a browser will happily follow a plain-HTTP link to this host, "
                        "which is the opening an attacker on the same network needs to downgrade or "
                        "intercept the session."
                    ),
                    evidence="No Strict-Transport-Security header on the HTTPS response.",
                    remediation=(
                        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all "
                        "HTTPS responses. Add 'preload' only once every subdomain is HTTPS-only."
                    ),
                    reference="OWASP Secure Headers Project: Strict-Transport-Security",
                )
            )
        elif _hsts_max_age(hsts) < MIN_HSTS_MAX_AGE:
            findings.append(
                Finding(
                    check_id="HDR-002",
                    title="HSTS max-age is short",
                    severity=Severity.LOW,
                    detail="A short HSTS lifetime leaves a window where the downgrade protection lapses.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Raise max-age to at least 15552000 (180 days); 31536000 (1 year) is typical.",
                    reference="OWASP Secure Headers Project: Strict-Transport-Security",
                )
            )

    # --- Content-Security-Policy ------------------------------------------
    csp = response.get("Content-Security-Policy")
    if not csp:
        findings.append(
            Finding(
                check_id="HDR-010",
                title="Content-Security-Policy header missing",
                severity=Severity.MEDIUM,
                detail=(
                    "CSP is the main browser-side control against cross-site scripting and injected "
                    "third-party script. Without it, a single unescaped parameter is usually enough "
                    "for script execution."
                ),
                evidence="No Content-Security-Policy header on the response.",
                remediation=(
                    "Start with a report-only policy ('Content-Security-Policy-Report-Only') to find "
                    "inline scripts, then enforce 'default-src 'self'' with explicit allow-lists."
                ),
                reference="OWASP Content Security Policy Cheat Sheet",
            )
        )
    elif "unsafe-inline" in csp:
        findings.append(
            Finding(
                check_id="HDR-011",
                title="CSP permits inline script ('unsafe-inline')",
                severity=Severity.LOW,
                detail=(
                    "'unsafe-inline' re-enables exactly the injection CSP exists to stop, so the policy "
                    "looks protective without providing much protection."
                ),
                evidence=f"Content-Security-Policy: {csp}",
                remediation="Move inline handlers into files or use per-response nonces/hashes instead.",
                reference="OWASP Content Security Policy Cheat Sheet",
            )
        )

    # --- Clickjacking -----------------------------------------------------
    frame_options = response.get("X-Frame-Options")
    frame_ancestors = csp and "frame-ancestors" in csp
    if not frame_options and not frame_ancestors:
        findings.append(
            Finding(
                check_id="HDR-020",
                title="No framing protection (clickjacking)",
                severity=Severity.MEDIUM,
                detail=(
                    "With no X-Frame-Options and no CSP frame-ancestors directive, this page can be "
                    "loaded inside an attacker's iframe and used to trick a logged-in user into "
                    "clicking something they did not intend."
                ),
                evidence="Neither X-Frame-Options nor a CSP frame-ancestors directive was present.",
                remediation=(
                    "Send 'X-Frame-Options: DENY' (or SAMEORIGIN if framing is needed), and add "
                    "'frame-ancestors 'none'' to the CSP for modern browsers."
                ),
                reference="OWASP Clickjacking Defense Cheat Sheet",
            )
        )

    # --- MIME sniffing ----------------------------------------------------
    if not response.get("X-Content-Type-Options"):
        findings.append(
            Finding(
                check_id="HDR-030",
                title="X-Content-Type-Options header missing",
                severity=Severity.LOW,
                detail=(
                    "Browsers may sniff a response into a different type than declared, which is how an "
                    "uploaded image can be executed as HTML or script."
                ),
                evidence="No X-Content-Type-Options header.",
                remediation="Send 'X-Content-Type-Options: nosniff' on every response.",
                reference="OWASP Secure Headers Project",
            )
        )

    # --- Referrer policy --------------------------------------------------
    if not response.get("Referrer-Policy"):
        findings.append(
            Finding(
                check_id="HDR-040",
                title="Referrer-Policy header missing",
                severity=Severity.LOW,
                detail=(
                    "By default the full URL of this page can leak to third parties in the Referer "
                    "header, including query strings that sometimes carry tokens or identifiers."
                ),
                evidence="No Referrer-Policy header.",
                remediation="Send 'Referrer-Policy: strict-origin-when-cross-origin' as a sensible default.",
                reference="OWASP Secure Headers Project",
            )
        )

    # --- Permissions policy ----------------------------------------------
    if not response.get("Permissions-Policy"):
        findings.append(
            Finding(
                check_id="HDR-050",
                title="Permissions-Policy header missing",
                severity=Severity.INFO,
                detail=(
                    "Optional hardening: without it, embedded third-party frames inherit access to "
                    "camera, microphone, and geolocation unless each is explicitly denied."
                ),
                evidence="No Permissions-Policy header.",
                remediation="Deny features the site does not use, e.g. 'camera=(), microphone=(), geolocation=()'.",
                reference="OWASP Secure Headers Project",
            )
        )

    return findings

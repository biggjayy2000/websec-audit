"""CORS checks: does the app reflect an arbitrary Origin to unauthenticated callers?"""

from __future__ import annotations

from typing import List

from ..http import ScanError
from ..models import Context, Finding, Severity

PROBE_ORIGIN = "https://origin-probe.invalid"


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    try:
        response = ctx.session.fetch(ctx.target.base + "/", extra_headers={"Origin": PROBE_ORIGIN})
    except ScanError:
        return findings

    ctx.probe = response
    allow_origin = response.get("Access-Control-Allow-Origin", "")
    allow_creds = (response.get("Access-Control-Allow-Credentials", "") or "").lower() == "true"
    reflected = allow_origin.strip() == PROBE_ORIGIN

    if reflected and allow_creds:
        findings.append(
            Finding(
                check_id="CORS-001",
                title="CORS reflects any Origin with credentials",
                severity=Severity.HIGH,
                detail=(
                    "The app echoes back whatever Origin the caller sends and permits credentials. Any "
                    "site can therefore make authenticated cross-origin requests on behalf of a logged-in "
                    "user and read the response - which is a complete bypass of the same-origin policy."
                ),
                evidence=f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {allow_origin}; Access-Control-Allow-Credentials: true",
                remediation=(
                    "Allow-list specific trusted origins server-side; never reflect the incoming Origin. "
                    "Do not combine a wildcard or reflected origin with credentials."
                ),
                reference="OWASP WSTG: Test Cross Origin Resource Sharing",
            )
        )
    elif reflected:
        findings.append(
            Finding(
                check_id="CORS-002",
                title="CORS reflects an arbitrary Origin",
                severity=Severity.MEDIUM,
                detail=(
                    "Any website can read this endpoint's responses. Without credentials the impact is "
                    "lower, but it still leaks content that was meant to be same-origin only."
                ),
                evidence=f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {allow_origin}",
                remediation="Replace reflection with an explicit allow-list of trusted origins.",
                reference="OWASP WSTG: Test Cross Origin Resource Sharing",
            )
        )
    elif allow_origin.strip() == "*" and allow_creds:
        findings.append(
            Finding(
                check_id="CORS-003",
                title="CORS wildcard combined with credentials",
                severity=Severity.MEDIUM,
                detail=(
                    "Browsers reject this combination, so the intended cross-origin feature is broken. "
                    "It usually signals a copied snippet rather than a designed policy."
                ),
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                remediation="Use an explicit allow-list when credentials are required; otherwise drop the credentials flag.",
                reference="OWASP WSTG: Test Cross Origin Resource Sharing",
            )
        )

    return findings

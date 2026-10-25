"""HTTP method exposure: TRACE and write verbs advertised by the server."""

from __future__ import annotations

from typing import List

from ..http import ScanError
from ..models import Context, Finding, Severity


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    try:
        response = ctx.session.fetch(ctx.target.base + "/", method="OPTIONS")
    except ScanError:
        return findings

    ctx.options = response
    allow = response.get("Allow") or response.get("Access-Control-Allow-Methods") or ""
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    if not methods:
        return findings

    if "TRACE" in methods:
        findings.append(
            Finding(
                check_id="METH-001",
                title="TRACE method enabled",
                severity=Severity.MEDIUM,
                detail=(
                    "TRACE echoes the request back to the caller. Combined with a scripting weakness it "
                    "lets an attacker read cookies and authentication headers that the browser attaches."
                ),
                evidence=f"Allow: {allow}",
                remediation="Disable TRACE at the server (TraceEnable off in Apache) and advertise only the methods the app uses.",
                reference="OWASP WSTG: Test HTTP Methods",
            )
        )

    risky = sorted(methods & {"PUT", "DELETE", "PATCH"})
    if risky:
        findings.append(
            Finding(
                check_id="METH-002",
                title="Write methods advertised by the server",
                severity=Severity.LOW,
                detail=(
                    "Advertising PUT/DELETE is not proof they are exploitable, but it widens the surface: "
                    "a forgotten handler that accepts PUT can allow file upload without authentication."
                ),
                evidence=f"{', '.join(risky)} advertised in Allow: {allow}",
                remediation="Disable unused verbs and require authentication and authorization on any write route.",
                reference="OWASP WSTG: Test HTTP Methods",
            )
        )

    return findings

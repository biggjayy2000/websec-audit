"""Plain-HTTP redirect behaviour: does port 80 actually send users to HTTPS?"""

from __future__ import annotations

from typing import List

from ..http import ScanError
from ..models import Context, Finding, Severity


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    if ctx.target.scheme != "https":
        return findings  # already reported as a plain-HTTP finding by the TLS check

    host = ctx.target.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    plain_url = f"http://{host}/"

    try:
        response = ctx.session.fetch(plain_url, follow=False)
    except ScanError:
        return findings  # port 80 closed is a fine outcome, not a finding

    location = response.get("Location", "")
    upgraded = response.status in (301, 302, 307, 308) and location.lower().startswith("https://")

    if not upgraded:
        findings.append(
            Finding(
                check_id="REDIR-001",
                title="HTTP does not redirect to HTTPS",
                severity=Severity.MEDIUM,
                detail=(
                    "Users who type the bare domain, or follow an old link, stay on an unencrypted "
                    "connection instead of being upgraded to HTTPS."
                ),
                evidence=f"GET {plain_url} -> HTTP {response.status}"
                + (f", Location: {location}" if location else " with no redirect"),
                remediation="Return a 301 to the HTTPS URL on port 80 for every path, and add HSTS afterwards.",
                reference="OWASP Transport Layer Security Cheat Sheet",
            )
        )

    return findings

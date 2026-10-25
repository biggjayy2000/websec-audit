"""Cookie attribute checks (Secure / HttpOnly / SameSite)."""

from __future__ import annotations

from typing import Dict, List

from ..models import Context, Finding, Severity

SESSION_HINTS = ("sess", "sid", "auth", "jwt", "token", "remember")


def parse_cookie(raw: str) -> Dict[str, str]:
    """'name=value; Path=/; Secure' -> {name, value, path, secure}."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    parsed: Dict[str, str] = {}
    if parts:
        name, _, value = parts[0].partition("=")
        parsed["name"] = name.strip()
        parsed["value"] = value.strip()
    for part in parts[1:]:
        key, _, value = part.partition("=")
        parsed[key.strip().lower()] = value.strip() or "true"
    return parsed


def _is_session(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SESSION_HINTS)


def run(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    cookies = [parse_cookie(c) for c in ctx.response.get_all("Set-Cookie")]
    if not cookies:
        return findings

    missing_secure, missing_httponly, missing_samesite, none_without_secure = [], [], [], []

    for cookie in cookies:
        name = cookie.get("name", "?")
        if "secure" not in cookie:
            missing_secure.append((name, _is_session(name)))
        if "httponly" not in cookie:
            missing_httponly.append((name, _is_session(name)))
        if "samesite" not in cookie:
            missing_samesite.append(name)
        elif cookie.get("samesite", "").lower() == "none" and "secure" not in cookie:
            none_without_secure.append(name)

    if missing_secure:
        privileged = any(is_session for _, is_session in missing_secure)
        names = ", ".join(name for name, _ in missing_secure)
        findings.append(
            Finding(
                check_id="COOK-001",
                title="Cookie set without the Secure flag",
                severity=Severity.HIGH if privileged else Severity.MEDIUM,
                detail=(
                    "A cookie without Secure is sent over plain HTTP as well, so anyone on the path "
                    "can read it. For a session identifier that means account takeover."
                ),
                evidence=f"Set-Cookie without Secure: {names}",
                remediation=(
                    "Add 'Secure' to every cookie, and serve the whole site over HTTPS. Session "
                    "cookies in particular must never travel unencrypted."
                ),
                reference="OWASP Session Management Cheat Sheet",
            )
        )

    if missing_httponly:
        privileged = any(is_session for _, is_session in missing_httponly)
        names = ", ".join(name for name, _ in missing_httponly)
        findings.append(
            Finding(
                check_id="COOK-002",
                title="Cookie set without HttpOnly",
                severity=Severity.MEDIUM if privileged else Severity.LOW,
                detail=(
                    "Without HttpOnly, JavaScript can read the cookie. Every cross-site scripting bug "
                    "then becomes session theft rather than a scripted alert."
                ),
                evidence=f"Set-Cookie without HttpOnly: {names}",
                remediation="Add 'HttpOnly' to any cookie the browser scripting layer does not need.",
                reference="OWASP Session Management Cheat Sheet",
            )
        )

    if missing_samesite:
        findings.append(
            Finding(
                check_id="COOK-003",
                title="Cookie set without SameSite",
                severity=Severity.LOW,
                detail=(
                    "Cookies with no SameSite attribute are sent on cross-site requests in older "
                    "browser behaviour, which weakens the default defence against cross-site request forgery."
                ),
                evidence=f"Set-Cookie without SameSite: {', '.join(missing_samesite)}",
                remediation="Add 'SameSite=Lax' (or Strict) and set SameSite=None only when a cross-site flow truly needs it.",
                reference="OWASP Session Management Cheat Sheet",
            )
        )

    if none_without_secure:
        findings.append(
            Finding(
                check_id="COOK-004",
                title="Cookie uses SameSite=None without Secure",
                severity=Severity.HIGH,
                detail=(
                    "Browsers reject this combination, so the cookie silently fails in some browsers "
                    "and the intended cross-site behaviour may be falling back to something weaker."
                ),
                evidence=f"Set-Cookie SameSite=None without Secure: {', '.join(none_without_secure)}",
                remediation="Either add Secure (required with SameSite=None) or use SameSite=Lax/Strict.",
                reference="OWASP Session Management Cheat Sheet",
            )
        )

    return findings

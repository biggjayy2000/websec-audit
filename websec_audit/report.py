"""Report rendering: Markdown for humans, JSON for tooling, ANSI for the terminal."""

from __future__ import annotations

import json
from typing import List

from .models import ScanResult, Severity

COLORS = {
    "Critical": "\033[1;35m",
    "High": "\033[1;31m",
    "Medium": "\033[1;33m",
    "Low": "\033[1;36m",
    "Info": "\033[1;37m",
}
RESET = "\033[0m"
DIM = "\033[2m"


def _severity_block(result: ScanResult) -> str:
    counts = result.counts()
    rows = ["| Severity | Count |", "| --- | --- |"]
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        rows.append(f"| {severity.value} | {counts[severity.value]} |")
    return "\n".join(rows)


def render_markdown(result: ScanResult) -> str:
    lines: List[str] = []
    lines.append(f"# Web Security Assessment - {result.target}")
    lines.append("")
    lines.append(f"- **Target:** {result.target}")
    lines.append(f"- **Started:** {result.started}")
    lines.append(f"- **Duration:** {result.duration:.1f}s across {result.request_count} requests")
    lines.append(f"- **Findings:** {len(result.findings)}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(_severity_block(result))
    lines.append("")

    if result.errors:
        lines.append("## Scan errors")
        lines.append("")
        for error in result.errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings. Every check in this run passed.")
        lines.append("")

    for index, finding in enumerate(result.sorted_findings(), start=1):
        lines.append(f"### {index}. [{finding.severity.value}] {finding.title}")
        lines.append("")
        lines.append(f"- **Check:** `{finding.check_id}`")
        lines.append(f"- **Why it matters:** {finding.detail}")
        lines.append(f"- **Evidence:** `{finding.evidence}`")
        lines.append(f"- **Remediation:** {finding.remediation}")
        if finding.reference:
            lines.append(f"- **Reference:** {finding.reference}")
        lines.append("")

    lines.append("## Scope and method")
    lines.append("")
    lines.append(
        "Only targets the operator is authorized to test were contacted. Checks are passive: ordinary "
        "HTTP GET/OPTIONS requests, no payloads, no authentication attempts, no writes. Severity reflects "
        "the weakness observed in this configuration, not a confirmed exploitation."
    )
    lines.append("")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "target": result.target,
        "started": result.started,
        "duration_seconds": round(result.duration, 2),
        "requests": result.request_count,
        "counts": result.counts(),
        "errors": result.errors,
        "findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "detail": f.detail,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "reference": f.reference,
            }
            for f in result.sorted_findings()
        ],
    }
    return json.dumps(payload, indent=2)


def render_console(result: ScanResult, color: bool = True, verbose: bool = True) -> str:
    def paint(text: str, severity: str) -> str:
        if not color:
            return text
        return f"{COLORS.get(severity, '')}{text}{RESET}"

    lines: List[str] = []
    lines.append("")
    lines.append(f"  Target   {result.target}")
    lines.append(f"  Scanned  {result.started}  ({result.duration:.1f}s, {result.request_count} requests)")
    lines.append("")

    counts = result.counts()
    summary = "  ".join(
        paint(f"{severity.value} {counts[severity.value]}", severity.value)
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    lines.append(f"  {summary}")
    lines.append("")

    for finding in result.sorted_findings():
        tag = paint(f"[{finding.severity.value:^8}]", finding.severity.value)
        lines.append(f"  {tag} {finding.check_id}  {finding.title}")
        if verbose:
            lines.append(f"             {finding.evidence}")
    lines.append("")

    for error in result.errors:
        lines.append(f"  {paint('scan error', 'Medium')}: {error}")

    return "\n".join(lines)

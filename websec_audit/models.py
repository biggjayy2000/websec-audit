"""Data model for a scan: findings, severities, and the scan context."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .http import Response, TLSInfo


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


_RANK = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


@dataclass(frozen=True)
class Finding:
    """A single observed weakness, with the evidence that supports it."""

    check_id: str
    title: str
    severity: Severity
    detail: str
    evidence: str
    remediation: str
    reference: str = ""

    @property
    def rank(self) -> int:
        return _RANK[self.severity.value]


@dataclass
class Target:
    url: str
    host: str
    scheme: str
    port: int

    @property
    def base(self) -> str:
        default_port = (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        )
        host = self.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"  # IPv6 literal
        return f"{self.scheme}://{host}" + ("" if default_port else f":{self.port}")


@dataclass
class Context:
    """Everything the checks need, gathered once so they stay pure-ish and testable."""

    target: Target
    response: Response
    session: object  # Session
    tls: Optional[TLSInfo] = None
    probe: Optional[Response] = None  # CORS probe response
    options: Optional[Response] = None  # OPTIONS response
    fetched: dict = field(default_factory=dict)  # path -> Response


@dataclass
class ScanResult:
    target: str
    started: str
    duration: float
    request_count: int
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.check_id))

    def counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def exit_code(self, fail_on: str = "High") -> int:
        """Non-zero when anything at or above ``fail_on`` was found (CI-friendly)."""
        threshold = _RANK[Severity(fail_on).value]
        return 1 if any(f.rank <= threshold for f in self.findings) else 0

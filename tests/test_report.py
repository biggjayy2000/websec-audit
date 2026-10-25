"""Report tests: the output is the deliverable, so it gets asserted too."""

import json
import unittest

from websec_audit.models import Finding, ScanResult, Severity
from websec_audit.report import render_console, render_json, render_markdown


def sample_result() -> ScanResult:
    return ScanResult(
        target="https://example.test/",
        started="2026-01-01 12:00:00",
        duration=1.234,
        request_count=7,
        findings=[
            Finding(
                check_id="HDR-010",
                title="Content-Security-Policy header missing",
                severity=Severity.MEDIUM,
                detail="CSP is the main browser-side control against XSS.",
                evidence="No Content-Security-Policy header.",
                remediation="Add a policy, starting report-only.",
                reference="OWASP CSP Cheat Sheet",
            ),
            Finding(
                check_id="TLS-001",
                title="Site served over plain HTTP",
                severity=Severity.HIGH,
                detail="Traffic is readable in transit.",
                evidence="Target scheme is http.",
                remediation="Serve over HTTPS.",
            ),
        ],
    )


class MarkdownReportTests(unittest.TestCase):
    def setUp(self):
        self.text = render_markdown(sample_result())

    def test_has_header_summary_and_findings(self):
        self.assertIn("# Web Security Assessment - https://example.test/", self.text)
        self.assertIn("## Summary", self.text)
        self.assertIn("## Findings", self.text)
        self.assertIn("## Scope and method", self.text)

    def test_findings_are_ordered_by_severity(self):
        high = self.text.index("Site served over plain HTTP")
        medium = self.text.index("Content-Security-Policy header missing")
        self.assertLess(high, medium, "High severity should be listed before Medium")

    def test_each_finding_carries_evidence_and_remediation(self):
        self.assertIn("**Evidence:**", self.text)
        self.assertIn("**Remediation:**", self.text)
        self.assertIn("**Why it matters:**", self.text)

    def test_counts_are_rendered(self):
        self.assertIn("| High | 1 |", self.text)
        self.assertIn("| Medium | 1 |", self.text)


class JsonReportTests(unittest.TestCase):
    def test_json_is_machine_readable(self):
        payload = json.loads(render_json(sample_result()))
        self.assertEqual(payload["counts"]["High"], 1)
        self.assertEqual(payload["findings"][0]["severity"], "High")
        self.assertEqual(len(payload["findings"]), 2)


class ConsoleReportTests(unittest.TestCase):
    def test_colour_can_be_disabled(self):
        plain = render_console(sample_result(), color=False)
        self.assertNotIn("\033[", plain)
        self.assertIn("HDR-010", plain)

    def test_quiet_mode_drops_evidence_lines(self):
        verbose = render_console(sample_result(), color=False, verbose=True)
        quiet = render_console(sample_result(), color=False, verbose=False)
        self.assertLess(len(quiet), len(verbose))


class ExitCodeTests(unittest.TestCase):
    def test_high_finding_fails_the_run(self):
        self.assertEqual(sample_result().exit_code("High"), 1)

    def test_low_threshold_only_passes_when_clean(self):
        self.assertEqual(sample_result().exit_code("Critical"), 0)

    def test_never_fails_when_threshold_disabled(self):
        result = sample_result()
        result.findings = []
        self.assertEqual(result.exit_code("Critical"), 0)


if __name__ == "__main__":
    unittest.main()

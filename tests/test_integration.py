"""End-to-end: scan a real local server over real sockets and check the report."""

import contextlib
import io
import json
import os
import tempfile
import unittest

from websec_audit.cli import main
from websec_audit.report import render_json, render_markdown
from websec_audit.scanner import scan

from .support import FixtureServer


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FixtureServer().__enter__()
        cls.result = scan(cls.server.base, delay=0.0, timeout=5.0)

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)

    def ids(self):
        return {f.check_id for f in self.result.findings}

    def test_scan_completes_without_errors(self):
        self.assertEqual(self.result.errors, [])
        self.assertGreater(self.result.request_count, 5)

    def test_header_and_cookie_findings_present(self):
        # HDR-001 (HSTS) is HTTPS-only, so a plain-HTTP fixture is expected not to raise it.
        self.assertTrue({"HDR-010", "HDR-020", "COOK-001"}.issubset(self.ids()))

    def test_tls_finding_for_plain_http_fixture(self):
        self.assertIn("TLS-001", self.ids())

    def test_exposed_paths_found_over_the_wire(self):
        self.assertTrue({"DISC-101", "DISC-102", "DISC-106"}.issubset(self.ids()))

    def test_trace_and_cors_found_over_the_wire(self):
        self.assertTrue({"METH-001", "CORS-001"}.issubset(self.ids()))

    def test_findings_are_sorted_with_high_first(self):
        severities = [f.severity.value for f in self.result.sorted_findings()]
        self.assertEqual(severities[0], "High")
        self.assertEqual(severities, sorted(severities, key=lambda s: ["Critical", "High", "Medium", "Low", "Info"].index(s)))

    def test_markdown_report_contains_real_evidence(self):
        text = render_markdown(self.result)
        self.assertIn(self.server.base, text)
        self.assertIn("ref: refs/heads/main", text)  # the actual .git/HEAD body
        self.assertIn("Access-Control-Allow-Origin", text)

    def test_json_report_round_trips(self):
        payload = json.loads(render_json(self.result))
        self.assertEqual(len(payload["findings"]), len(self.result.findings))
        self.assertTrue(all("evidence" in f for f in payload["findings"]))

    def test_cli_fails_on_high_and_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            markdown_path = os.path.join(tmp, "report.md")
            json_path = os.path.join(tmp, "report.json")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([
                    self.server.base,
                    "--delay", "0",
                    "--no-color",
                    "--quiet",
                    "--markdown", markdown_path,
                    "--json", json_path,
                ])
            self.assertEqual(code, 1, "a High finding must fail the run")
            self.assertTrue(os.path.getsize(markdown_path) > 500)
            with open(json_path, encoding="utf-8") as handle:
                self.assertIn("findings", json.load(handle))
            self.assertIn("Markdown report written", buffer.getvalue())


class CliScopeTests(unittest.TestCase):
    def test_public_target_is_refused_before_any_request(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = main(["8.8.8.8"])
        self.assertEqual(code, 2)
        self.assertIn("Out of scope", err.getvalue())


if __name__ == "__main__":
    unittest.main()

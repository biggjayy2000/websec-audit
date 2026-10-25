"""The scope guard is the most important code in this project: test it first."""

import unittest

from websec_audit.scanner import parse_target
from websec_audit.scope import ScopeError, check_target


class ScopeTests(unittest.TestCase):
    def test_loopback_is_always_in_scope(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            with self.subTest(host=host):
                self.assertIn("loopback", check_target(host))

    def test_public_target_is_refused_by_default(self):
        with self.assertRaises(ScopeError) as caught:
            check_target("8.8.8.8")
        self.assertIn("out of scope", str(caught.exception))

    def test_public_target_allowed_with_explicit_authorization(self):
        self.assertIn("authorized", check_target("8.8.8.8", authorized=True))

    def test_private_range_needs_its_own_flag(self):
        with self.assertRaises(ScopeError) as caught:
            check_target("192.168.1.10")
        self.assertIn("--allow-private", str(caught.exception))
        self.assertIn("private", check_target("192.168.1.10", allow_private=True))

    def test_link_local_range_is_private(self):
        with self.assertRaises(ScopeError):
            check_target("169.254.1.1")

    def test_unresolvable_host_is_reported_not_scanned(self):
        with self.assertRaises(ScopeError):
            check_target("this-host-does-not-exist.invalid")


class TargetParsingTests(unittest.TestCase):
    def test_bare_hostname_defaults_to_https(self):
        target = parse_target("example.com")
        self.assertEqual((target.scheme, target.port, target.url), ("https", 443, "https://example.com/"))

    def test_explicit_http_port_and_path_are_preserved(self):
        target = parse_target("http://127.0.0.1:8080/app")
        self.assertEqual((target.scheme, target.port), ("http", 8080))
        self.assertTrue(target.url.endswith("/app"))

    def test_base_omits_default_port(self):
        self.assertEqual(parse_target("https://example.com").base, "https://example.com")
        self.assertEqual(parse_target("https://example.com:8443").base, "https://example.com:8443")

    def test_bad_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_target("ftp://example.com")


if __name__ == "__main__":
    unittest.main()

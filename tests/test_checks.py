"""Check-level tests: each check gets a clean case and a broken case."""

import unittest

from websec_audit.checks import cookies, cors, disclosure, headers, methods, redirects, tls
from websec_audit.http import TLSInfo

from .support import StubSession, make_context, make_response


def ids(findings):
    return {f.check_id for f in findings}


HARDENED_HEADERS = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
]


class HeaderTests(unittest.TestCase):
    def test_hardened_site_produces_no_header_findings(self):
        response = make_response(headers=HARDENED_HEADERS)
        self.assertEqual(headers.run(make_context("https", response)), [])

    def test_missing_headers_are_all_reported(self):
        findings = headers.run(make_context("https", make_response()))
        self.assertTrue({"HDR-001", "HDR-010", "HDR-020", "HDR-030", "HDR-040"}.issubset(ids(findings)))

    def test_short_hsts_and_unsafe_inline_are_flagged(self):
        response = make_response(
            headers=[
                ("Strict-Transport-Security", "max-age=600"),
                ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'"),
                ("X-Frame-Options", "DENY"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Permissions-Policy", "camera=()"),
            ]
        )
        self.assertTrue({"HDR-002", "HDR-011"}.issubset(ids(headers.run(make_context("https", response)))))

    def test_csp_frame_ancestors_counts_as_clickjacking_protection(self):
        response = make_response(
            headers=[
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("Strict-Transport-Security", "max-age=31536000"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Permissions-Policy", "camera=()"),
            ]
        )
        self.assertNotIn("HDR-020", ids(headers.run(make_context("https", response))))


class CookieTests(unittest.TestCase):
    def test_secure_cookie_is_quiet(self):
        response = make_response(headers=[("Set-Cookie", "sessionid=abc; Secure; HttpOnly; SameSite=Lax")])
        self.assertEqual(cookies.run(make_context("https", response)), [])

    def test_session_cookie_without_flags_is_high_severity(self):
        response = make_response(headers=[("Set-Cookie", "sessionid=abc; Path=/")])
        found = ids(cookies.run(make_context("https", response)))
        self.assertIn("COOK-001", found)
        self.assertIn("COOK-002", found)
        self.assertIn("COOK-003", found)

    def test_samesite_none_without_secure(self):
        response = make_response(headers=[("Set-Cookie", "pref=1; SameSite=None")])
        self.assertIn("COOK-004", ids(cookies.run(make_context("https", response))))

    def test_parse_cookie_handles_attributes(self):
        parsed = cookies.parse_cookie("sessionid=abc; Path=/; HttpOnly; SameSite=Strict")
        self.assertEqual(parsed["name"], "sessionid")
        self.assertEqual(parsed["httponly"], "true")
        self.assertEqual(parsed["samesite"], "Strict")


class CorsTests(unittest.TestCase):
    def test_reflected_origin_with_credentials_is_high(self):
        response = make_response(headers=[
            ("Access-Control-Allow-Origin", cors.PROBE_ORIGIN),
            ("Access-Control-Allow-Credentials", "true"),
        ])
        findings = cors.run(make_context("https", make_response(), StubSession({"/": response})))
        self.assertEqual(ids(findings), {"CORS-001"})
        self.assertEqual(next(iter(findings)).severity.value, "High")

    def test_wildcard_alone_is_not_flagged(self):
        response = make_response(headers=[("Access-Control-Allow-Origin", "*")])
        findings = cors.run(make_context("https", make_response(), StubSession({"/": response})))
        self.assertEqual(findings, [])


class DisclosureTests(unittest.TestCase):
    def test_exposed_files_are_detected(self):
        routes = {
            "/.git/HEAD": make_response(body=b"ref: refs/heads/main\n"),
            "/.env": make_response(body=b"DB_PASSWORD=x\n"),
            "/backup.zip": make_response(body=b"PK\x03\x04rest"),
        }
        findings = disclosure.run(make_context("https", make_response(), StubSession(routes)))
        self.assertTrue({"DISC-101", "DISC-102", "DISC-106"}.issubset(ids(findings)))

    def test_banner_and_directory_listing(self):
        response = make_response(
            headers=[("Server", "Apache/2.4.49"), ("X-Powered-By", "PHP/7.4")],
            body=b"<title>Index of /</title>",
        )
        found = ids(disclosure.run(make_context("https", response)))
        self.assertTrue({"DISC-001", "DISC-020"}.issubset(found))

    def test_clean_site_has_no_disclosure_findings(self):
        response = make_response(headers=[("Server", "nginx")], body=b"<html>hello</html>")
        self.assertEqual(disclosure.run(make_context("https", response, StubSession({}))), [])

    def test_verbose_error_on_500(self):
        response = make_response(status=500, body=b"Traceback (most recent call last): ...")
        self.assertIn("DISC-010", ids(disclosure.run(make_context("https", response))))


class MethodTests(unittest.TestCase):
    def test_trace_enabled(self):
        response = make_response(headers=[("Allow", "GET, POST, OPTIONS, TRACE")])
        self.assertIn("METH-001", ids(methods.run(make_context("https", make_response(), StubSession({"/": response})))))

    def test_trace_absent(self):
        response = make_response(headers=[("Allow", "GET, POST, OPTIONS")])
        self.assertEqual(methods.run(make_context("https", make_response(), StubSession({"/": response}))), [])


class TLSTests(unittest.TestCase):
    def test_plain_http_is_high(self):
        findings = tls.run(make_context("http", make_response()))
        self.assertEqual(ids(findings), {"TLS-001"})

    def test_weak_protocol(self):
        ctx = make_context("https", make_response())
        ctx.tls = TLSInfo(version="TLSv1", cipher="AES128-SHA", trusted=True, not_after="Jan  1 00:00:00 2035 GMT")
        self.assertIn("TLS-010", ids(tls.run(ctx)))

    def test_untrusted_certificate(self):
        ctx = make_context("https", make_response())
        ctx.tls = TLSInfo(version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", trusted=False, error="self signed certificate")
        self.assertIn("TLS-020", ids(tls.run(ctx)))

    def test_expiring_and_expired_certificates(self):
        ctx = make_context("https", make_response())
        ctx.tls = TLSInfo(version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", trusted=True, not_after="Jan  1 00:00:00 2020 GMT")
        self.assertIn("TLS-030", ids(tls.run(ctx)))

        ctx.tls = TLSInfo(version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", trusted=True, not_after="Jan  1 00:00:00 2035 GMT")
        self.assertEqual(tls.run(ctx), [])


class RedirectTests(unittest.TestCase):
    def test_http_target_is_not_double_reported(self):
        self.assertEqual(redirects.run(make_context("http", make_response())), [])

    def test_https_target_without_redirect(self):
        plain = make_response(status=200)
        self.assertIn("REDIR-001", ids(redirects.run(make_context("https", make_response(), StubSession({"http://127.0.0.1/": plain})))))

    def test_https_target_with_redirect(self):
        plain = make_response(status=301, headers=[("Location", "https://127.0.0.1/")])
        self.assertEqual(redirects.run(make_context("https", make_response(), StubSession({"http://127.0.0.1/": plain}))), [])


if __name__ == "__main__":
    unittest.main()

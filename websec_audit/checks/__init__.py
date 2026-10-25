"""Checks are plain functions: Context in, list[Finding] out. Easy to test, easy to add."""

from . import cookies, cors, disclosure, headers, methods, redirects, tls

ALL_CHECKS = (
    ("Response headers", headers.run),
    ("Cookies", cookies.run),
    ("TLS", tls.run),
    ("Information disclosure", disclosure.run),
    ("HTTP methods", methods.run),
    ("CORS", cors.run),
    ("HTTPS redirect", redirects.run),
)

__all__ = ["ALL_CHECKS"]

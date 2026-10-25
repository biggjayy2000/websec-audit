"""Test helpers: hand-built responses, a stub session, and a deliberately bad local server."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable, Optional, Tuple

from websec_audit.http import Response, TLSInfo
from websec_audit.models import Context, Target


def make_response(
    url: str = "http://127.0.0.1/",
    status: int = 200,
    headers: Optional[Iterable[Tuple[str, str]]] = None,
    body: bytes = b"",
) -> Response:
    return Response(url=url, status=status, headers=list(headers or []), body=body, elapsed=0.01)


def make_context(scheme: str = "http", response: Optional[Response] = None, session=None) -> Context:
    target = Target(url=f"{scheme}://127.0.0.1/", host="127.0.0.1", scheme=scheme, port=443 if scheme == "https" else 80)
    return Context(
        target=target,
        response=response or make_response(url=target.url),
        session=session or StubSession({}),
        tls=TLSInfo(version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", trusted=True, not_after="Jan  1 00:00:00 2035 GMT"),
    )


class StubSession:
    """Returns canned responses keyed by URL suffix, so checks can be tested offline."""

    def __init__(self, routes: Dict[str, Response]):
        self.routes = routes
        self.requests = 0

    def fetch(self, url: str, method: str = "GET", extra_headers=None, follow: bool = True) -> Response:
        self.requests += 1
        for suffix, response in self.routes.items():
            if url.endswith(suffix):
                return response
        return make_response(url=url, status=404)


class _FixtureHandler(BaseHTTPRequestHandler):
    """A server that gets nearly everything wrong, used by the end-to-end test."""

    def log_message(self, *args):  # silence test output
        pass

    def _send(self, status: int, body: bytes, extra_headers: Optional[Dict[str, str]] = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "FixtureServer/1.4.2")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, b"", {"Allow": "GET, POST, OPTIONS, TRACE"})

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n")
        elif path == "/.env":
            self._send(200, b"DB_PASSWORD=hunter2\nAPI_KEY=not-a-real-key\n")
        elif path == "/backup.zip":
            self._send(200, b"PK\x03\x04fake-archive")
        elif path == "/robots.txt":
            self._send(404, b"not found")
        else:
            self._send(200, b"<html><head><title>Index of /</title></head><body>fixture</body></html>")


class FixtureServer:
    """Context manager that serves the misconfigured fixture on a free loopback port."""

    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc_info):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        return False

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

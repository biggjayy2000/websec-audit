#!/usr/bin/env python3
"""A deliberately insecure local server, for demoing the scanner.

Everything here is fake and bounded to loopback. Run it, scan it, delete it.

    python examples/demo_server.py --port 8000
    python -m websec_audit http://127.0.0.1:8000 --markdown examples/sample-report.md
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = b"<html><head><title>Index of /</title></head><body><h1>Demo store</h1></body></html>"


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")

    def _send(self, status: int, body: bytes, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Deliberately sloppy configuration follows.
        self.send_header("Server", "DemoServer/2.1.0")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "sessionid=demo-session-value; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for key, value in (extra or {}).items():
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
            self._send(200, b"DB_PASSWORD=demo-password\nSECRET_KEY=demo-key\n")
        elif path == "/backup.zip":
            self._send(200, b"PK\x03\x04demo-archive")
        elif path == "/server-status":
            self._send(200, b"<h1>Apache Server Status</h1>")
        else:
            self._send(200, INDEX)


def main() -> None:
    parser = argparse.ArgumentParser(description="Insecure demo server for websec-audit")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"Demo server on http://127.0.0.1:{args.port} (loopback only). Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

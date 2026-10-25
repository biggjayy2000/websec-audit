"""HTTP plumbing: one small session object, no third-party dependencies."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Tuple

USER_AGENT = "WebSecAudit/1.0 (+authorized portfolio assessment)"
BODY_LIMIT = 64 * 1024


class ScanError(RuntimeError):
    """Raised when a request cannot be completed at all."""


@dataclass
class Response:
    url: str
    status: int
    headers: List[Tuple[str, str]]
    body: bytes
    elapsed: float

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return default

    def get_all(self, name: str) -> List[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


@dataclass
class TLSInfo:
    version: str
    cipher: str
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    trusted: bool = True
    error: str = ""


class Session:
    """A deliberately boring HTTP client: timeouts, a small delay, no retries."""

    def __init__(self, timeout: float = 10.0, delay: float = 0.15, user_agent: str = USER_AGENT):
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.requests = 0
        # Lab targets often use self-signed certs; certificate trust is judged in the
        # TLS check instead, so the scan still collects evidence either way.
        self._tls_context = ssl.create_default_context()
        self._tls_context.check_hostname = False
        self._tls_context.verify_mode = ssl.CERT_NONE

    def fetch(
        self,
        url: str,
        method: str = "GET",
        extra_headers: Optional[dict] = None,
        follow: bool = True,
    ) -> Response:
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if extra_headers:
            headers.update(extra_headers)

        request = urllib.request.Request(url, method=method, headers=headers)
        # Connect directly: an assessment should see the target's real configuration,
        # not a corporate proxy's, and env proxies would make results unrepeatable.
        handlers: list = [
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._tls_context),
        ]
        if not follow:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, hdrs, newurl):  # noqa: D401
                    return None

            handlers.append(_NoRedirect())

        opener = urllib.request.build_opener(*handlers)
        started = time.monotonic()
        try:
            with opener.open(request, timeout=self.timeout) as raw:
                body = raw.read(BODY_LIMIT)
                response = Response(
                    url=url,
                    status=getattr(raw, "status", 200),
                    headers=list(raw.headers.items()),
                    body=body,
                    elapsed=time.monotonic() - started,
                )
        except urllib.error.HTTPError as exc:  # 4xx/5xx still carry useful headers
            body = exc.read(BODY_LIMIT)
            response = Response(
                url=url,
                status=exc.code,
                headers=list(exc.headers.items()) if exc.headers else [],
                body=body,
                elapsed=time.monotonic() - started,
            )
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
            raise ScanError(f"{method} {url} failed: {exc}") from exc
        finally:
            self.requests += 1
            if self.delay:
                time.sleep(self.delay)

        return response

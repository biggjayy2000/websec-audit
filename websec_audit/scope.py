"""Authorization guard.

The tool refuses to touch anything that is not loopback unless you say, twice,
that you are allowed to: once for private/lab ranges and once for public hosts.
Scope is checked *before* the first packet leaves the process.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List

LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class ScopeError(PermissionError):
    """The target is outside the permitted scope."""


def _resolve(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeError(f"Could not resolve '{host}': {exc}") from exc
    return sorted({info[4][0] for info in infos})


def _is_loopback(host: str, addresses: List[str]) -> bool:
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        pass
    return bool(addresses) and all(ipaddress.ip_address(a).is_loopback for a in addresses)


def _is_private(addresses: List[str]) -> bool:
    if not addresses:
        return False
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_link_local:
            continue
        return False
    return True


def check_target(host: str, allow_private: bool = False, authorized: bool = False) -> str:
    """Return a human-readable scope decision, or raise :class:`ScopeError`."""
    addresses = _resolve(host)

    if _is_loopback(host, addresses):
        return "loopback target (always in scope)"

    if _is_private(addresses) and allow_private:
        return "private/lab range (allowed by --allow-private)"

    if authorized:
        return "authorized by operator (--authorize)"

    if _is_private(addresses):
        raise ScopeError(
            f"'{host}' resolves to a private address but --allow-private was not passed.\n"
            "Only scan labs and networks you own or administer."
        )

    raise ScopeError(
        f"'{host}' is a public target and is out of scope by default.\n"
        "This tool is for authorized testing only. If you have written permission to test\n"
        "this host, re-run with --authorize and keep a copy of that permission."
    )

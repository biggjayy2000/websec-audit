"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .models import Severity
from .report import render_console, render_json, render_markdown
from .scanner import DEFAULT_DELAY, DEFAULT_TIMEOUT, scan
from .scope import ScopeError

BANNER = "websec-audit - authorized, passive web security assessment"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="websec-audit",
        description=(
            "Passive security assessment for sites you own or administer. Checks response headers, "
            "cookies, TLS, information disclosure, HTTP methods, CORS, and HTTPS redirects. "
            "Loopback targets are allowed by default; anything else needs explicit permission flags."
        ),
    )
    parser.add_argument("target", help="URL or hostname, e.g. http://localhost:3000")
    parser.add_argument("--markdown", metavar="PATH", help="write a Markdown report")
    parser.add_argument("--json", metavar="PATH", help="write a JSON report")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request timeout (s)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="pause between requests (s)")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="permit RFC1918 lab networks you administer",
    )
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="confirm you have written permission to test a public target",
    )
    parser.add_argument("--no-color", action="store_true", help="plain terminal output")
    parser.add_argument("--quiet", action="store_true", help="summary only, no evidence lines")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity] + ["never"],
        default=Severity.HIGH.value,
        help="exit non-zero when a finding at or above this severity exists (default: High)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _write(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    print(BANNER)
    print("Only scan what you are authorized to test.\n")

    try:
        result = scan(
            args.target,
            timeout=args.timeout,
            delay=args.delay,
            allow_private=args.allow_private,
            authorized=args.authorize,
        )
    except ScopeError as exc:
        print(f"Out of scope: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2

    print(render_console(result, color=not args.no_color, verbose=not args.quiet))

    if args.markdown:
        _write(args.markdown, render_markdown(result))
        print(f"Markdown report written to {args.markdown}")
    if args.json:
        _write(args.json, render_json(result))
        print(f"JSON report written to {args.json}")

    if args.fail_on == "never":
        return 0
    return result.exit_code(args.fail_on)

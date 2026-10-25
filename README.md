# websec-audit

A small, dependency-free web security assessment tool for **authorized** testing. It checks the
things that are usually wrong on a first deployment — missing security headers, session cookies
without flags, obsolete TLS, exposed `.git`/`.env` files, verbose errors, dangerous HTTP methods,
and CORS that trusts everyone — then writes a severity-ranked report with evidence and remediation.

Built and tested against local targets only. Nothing here exploits anything: every check is an
ordinary GET or OPTIONS request.

```
$ python -m websec_audit http://127.0.0.1:8000

  Target   http://127.0.0.1:8000/
  Scanned  2026-10-25 07:55:22  (1.4s, 9 requests)

  Critical 0  High 6  Medium 6  Low 4  Info 1

  [  High  ] DISC-101  Exposed Git repository
             GET /.git/HEAD -> HTTP 200, body: 'ref: refs/heads/main'
  [  High  ] CORS-001  CORS reflects any Origin with credentials
             Origin: https://origin-probe.invalid -> Access-Control-Allow-Origin: https://origin-probe.invalid; ...
  [ Medium ] METH-001  TRACE method enabled
             Allow: GET, POST, OPTIONS, TRACE
```

## Why it exists

I wanted a testing tool that produces the actual deliverable of an assessment — a report a
developer can act on — rather than a wall of raw output. Each finding carries four things:
what was observed, why it matters, the evidence, and how to fix it.

## Quick start

Requires Python 3.9+. No third-party packages.

```bash
git clone <your-repo-url>
cd websec-audit

# 1. Start the deliberately insecure demo server
python examples/demo_server.py --port 8000

# 2. Scan it, from a second terminal
python -m websec_audit http://127.0.0.1:8000 --markdown report.md
```

Run the tests:

```bash
python -m unittest discover -s tests -t . -v
```

## Scope and authorization

The tool will only leave loopback if you tell it to:

| Target | Requirement |
| --- | --- |
| `localhost`, `127.0.0.1`, `::1` | always allowed |
| Private ranges (`10/8`, `172.16/12`, `192.168/16`, link-local) | `--allow-private` |
| Anything public | `--authorize` |

Scope is resolved and checked **before the first request**. A hostname that points at a public
address is refused even if it looks local, which closes the obvious DNS trick.

Only scan systems you own or have written permission to test. Scanning someone else's site is
not a "lab" — depending on where you live it can be a criminal offence regardless of intent.

## Usage

```
python -m websec_audit TARGET [options]

  --markdown PATH     write a Markdown report
  --json PATH         write a JSON report
  --timeout SECONDS   per-request timeout (default 10)
  --delay SECONDS     pause between requests (default 0.15)
  --allow-private     permit RFC1918 lab networks
  --authorize         confirm written permission for a public target
  --no-color          plain output
  --quiet             summary only
  --fail-on LEVEL     exit 1 at or above this severity (default High, or 'never')
```

Exit codes: `0` clean for the chosen threshold, `1` findings at/above it, `2` refused or invalid
target. That makes it usable as a CI gate on a staging URL.

## What it checks

| Area | Examples |
| --- | --- |
| Response headers (`HDR-*`) | HSTS, CSP, clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy |
| Cookies (`COOK-*`) | `Secure`, `HttpOnly`, `SameSite`, and the invalid `SameSite=None` without `Secure` |
| TLS (`TLS-*`) | plain HTTP, obsolete protocol versions, untrusted certificate, expiry |
| Information disclosure (`DISC-*`) | version banners, stack traces on 5xx, directory listing, `.git/HEAD`, `.env`, `server-status`, `phpinfo`, `.DS_Store`, `backup.zip` |
| HTTP methods (`METH-*`) | `TRACE` enabled, write verbs advertised |
| CORS (`CORS-*`) | origin reflection with credentials, wildcard with credentials |
| Redirects (`REDIR-*`) | port 80 not upgrading to HTTPS |

Adding a check is one function: take a `Context`, return `list[Finding]`, register it in
`websec_audit/checks/__init__.py`.

## Design notes

- **Dependency-free.** `urllib`, `ssl`, `socket`. Nothing to install, so it runs anywhere Python does.
- **Scope is code, not a README promise.** The guard runs before the session is even created.
- **Checks are pure-ish.** They receive a `Context` and return findings, which is why 53 tests can
  cover them without mocking a network stack; one integration test still scans a real socket.
- **Evidence is quoted.** Findings show the actual header or body fragment that matched, so a
  reader can verify the claim instead of trusting it.
- **Proxies are bypassed.** An assessment should see the target's real configuration.

## Limitations

- Passive only: it reports configuration weaknesses, not confirmed exploitability.
- No authenticated scanning. A logged-in session would unlock a larger set of checks.
- Single response per check; it does not crawl, and only tests the URL you give it.
- Header checks are HTTP-level; JavaScript-built DOM-based issues are out of scope.
- Severity is a judgement call baked into each check, not scored from CVSS.

## Sample output

- [`examples/sample-report.md`](examples/sample-report.md) — full report against the demo server
- [`examples/sample-report.json`](examples/sample-report.json) — same data for tooling

## License

MIT. Use it on systems you are allowed to test.

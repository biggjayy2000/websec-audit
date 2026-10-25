# Web Security Assessment - http://127.0.0.1:8000/

- **Target:** http://127.0.0.1:8000/
- **Started:** 2026-10-25 08:03:25
- **Duration:** 1.4s across 9 requests
- **Findings:** 17

## Summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 6 |
| Medium | 6 |
| Low | 4 |
| Info | 1 |

## Findings

### 1. [High] Cookie set without the Secure flag

- **Check:** `COOK-001`
- **Why it matters:** A cookie without Secure is sent over plain HTTP as well, so anyone on the path can read it. For a session identifier that means account takeover.
- **Evidence:** `Set-Cookie without Secure: sessionid`
- **Remediation:** Add 'Secure' to every cookie, and serve the whole site over HTTPS. Session cookies in particular must never travel unencrypted.
- **Reference:** OWASP Session Management Cheat Sheet

### 2. [High] CORS reflects any Origin with credentials

- **Check:** `CORS-001`
- **Why it matters:** The app echoes back whatever Origin the caller sends and permits credentials. Any site can therefore make authenticated cross-origin requests on behalf of a logged-in user and read the response - which is a complete bypass of the same-origin policy.
- **Evidence:** `Origin: https://origin-probe.invalid -> Access-Control-Allow-Origin: https://origin-probe.invalid; Access-Control-Allow-Credentials: true`
- **Remediation:** Allow-list specific trusted origins server-side; never reflect the incoming Origin. Do not combine a wildcard or reflected origin with credentials.
- **Reference:** OWASP WSTG: Test Cross Origin Resource Sharing

### 3. [High] Exposed Git repository

- **Check:** `DISC-101`
- **Why it matters:** The repository metadata is readable, which usually allows the full source history - including credentials and secrets that were deleted from the current code - to be recovered.
- **Evidence:** `GET /.git/HEAD -> HTTP 200, body: 'ref: refs/heads/main'`
- **Remediation:** Block dotfiles at the web server, remove the .git directory from the document root, and rotate any secret that was ever committed.
- **Reference:** OWASP WSTG: Review Webpage Content for Information Leakage

### 4. [High] Exposed environment file (.env)

- **Check:** `DISC-102`
- **Why it matters:** Environment files normally hold database passwords, API keys, and signing secrets; readable from the web they hand an attacker the keys to the application.
- **Evidence:** `GET /.env -> HTTP 200, body: 'DB_PASSWORD=demo-password SECRET_KEY=demo-key'`
- **Remediation:** Move .env outside the document root, deny the path at the server, and rotate every credential it contained.
- **Reference:** OWASP WSTG: Review Webpage Content for Information Leakage

### 5. [High] Backup archive reachable

- **Check:** `DISC-106`
- **Why it matters:** A downloadable backup typically contains source code, configuration, and database dumps - often the fastest route from a web request to full compromise.
- **Evidence:** `GET /backup.zip -> HTTP 200, body: '50 4b 03 04 64 65 6d 6f 2d 61 72 63'`
- **Remediation:** Store backups outside the web root and require authentication for any download route.
- **Reference:** OWASP WSTG: Review Webpage Content for Information Leakage

### 6. [High] Site served over plain HTTP

- **Check:** `TLS-001`
- **Why it matters:** Everything on this connection - credentials, session cookies, page content - is readable and modifiable by anyone positioned on the path.
- **Evidence:** `Target scheme is http.`
- **Remediation:** Serve the site over HTTPS only, redirect port 80 to 443, and add HSTS once the redirect has been verified.
- **Reference:** OWASP Transport Layer Security Cheat Sheet

### 7. [Medium] Cookie set without HttpOnly

- **Check:** `COOK-002`
- **Why it matters:** Without HttpOnly, JavaScript can read the cookie. Every cross-site scripting bug then becomes session theft rather than a scripted alert.
- **Evidence:** `Set-Cookie without HttpOnly: sessionid`
- **Remediation:** Add 'HttpOnly' to any cookie the browser scripting layer does not need.
- **Reference:** OWASP Session Management Cheat Sheet

### 8. [Medium] Directory listing enabled

- **Check:** `DISC-020`
- **Why it matters:** The server prints an index of the directory, which exposes files that were never meant to be browsed - drafts, exports, and old backups.
- **Evidence:** `Root response body contains an 'Index of /' title.`
- **Remediation:** Disable auto-indexing (Options -Indexes in Apache, autoindex off in nginx).
- **Reference:** OWASP WSTG: Directory Traversal and File Include

### 9. [Medium] Apache server-status page exposed

- **Check:** `DISC-103`
- **Why it matters:** The status page lists active requests and client addresses, which reveals internal URLs, traffic patterns, and sometimes other users' activity.
- **Evidence:** `GET /server-status -> HTTP 200, body: '<h1>Apache Server Status</h1>'`
- **Remediation:** Restrict /server-status to localhost, or disable mod_status in production.
- **Reference:** OWASP WSTG: Review Webpage Content for Information Leakage

### 10. [Medium] Content-Security-Policy header missing

- **Check:** `HDR-010`
- **Why it matters:** CSP is the main browser-side control against cross-site scripting and injected third-party script. Without it, a single unescaped parameter is usually enough for script execution.
- **Evidence:** `No Content-Security-Policy header on the response.`
- **Remediation:** Start with a report-only policy ('Content-Security-Policy-Report-Only') to find inline scripts, then enforce 'default-src 'self'' with explicit allow-lists.
- **Reference:** OWASP Content Security Policy Cheat Sheet

### 11. [Medium] No framing protection (clickjacking)

- **Check:** `HDR-020`
- **Why it matters:** With no X-Frame-Options and no CSP frame-ancestors directive, this page can be loaded inside an attacker's iframe and used to trick a logged-in user into clicking something they did not intend.
- **Evidence:** `Neither X-Frame-Options nor a CSP frame-ancestors directive was present.`
- **Remediation:** Send 'X-Frame-Options: DENY' (or SAMEORIGIN if framing is needed), and add 'frame-ancestors 'none'' to the CSP for modern browsers.
- **Reference:** OWASP Clickjacking Defense Cheat Sheet

### 12. [Medium] TRACE method enabled

- **Check:** `METH-001`
- **Why it matters:** TRACE echoes the request back to the caller. Combined with a scripting weakness it lets an attacker read cookies and authentication headers that the browser attaches.
- **Evidence:** `Allow: GET, POST, OPTIONS, TRACE`
- **Remediation:** Disable TRACE at the server (TraceEnable off in Apache) and advertise only the methods the app uses.
- **Reference:** OWASP WSTG: Test HTTP Methods

### 13. [Low] Cookie set without SameSite

- **Check:** `COOK-003`
- **Why it matters:** Cookies with no SameSite attribute are sent on cross-site requests in older browser behaviour, which weakens the default defence against cross-site request forgery.
- **Evidence:** `Set-Cookie without SameSite: sessionid`
- **Remediation:** Add 'SameSite=Lax' (or Strict) and set SameSite=None only when a cross-site flow truly needs it.
- **Reference:** OWASP Session Management Cheat Sheet

### 14. [Low] Server software and version disclosed

- **Check:** `DISC-001`
- **Why it matters:** Not exploitable on its own, but it tells an attacker which known vulnerabilities to try first and saves them the reconnaissance.
- **Evidence:** `Server: BaseHTTP Python/3.15.0; X-Powered-By: PHP/7.4.3`
- **Remediation:** Suppress version strings (ServerTokens Prod, expose_php Off) or front the app with a proxy that normalises headers.
- **Reference:** OWASP WSTG: Fingerprint Web Server

### 15. [Low] X-Content-Type-Options header missing

- **Check:** `HDR-030`
- **Why it matters:** Browsers may sniff a response into a different type than declared, which is how an uploaded image can be executed as HTML or script.
- **Evidence:** `No X-Content-Type-Options header.`
- **Remediation:** Send 'X-Content-Type-Options: nosniff' on every response.
- **Reference:** OWASP Secure Headers Project

### 16. [Low] Referrer-Policy header missing

- **Check:** `HDR-040`
- **Why it matters:** By default the full URL of this page can leak to third parties in the Referer header, including query strings that sometimes carry tokens or identifiers.
- **Evidence:** `No Referrer-Policy header.`
- **Remediation:** Send 'Referrer-Policy: strict-origin-when-cross-origin' as a sensible default.
- **Reference:** OWASP Secure Headers Project

### 17. [Info] Permissions-Policy header missing

- **Check:** `HDR-050`
- **Why it matters:** Optional hardening: without it, embedded third-party frames inherit access to camera, microphone, and geolocation unless each is explicitly denied.
- **Evidence:** `No Permissions-Policy header.`
- **Remediation:** Deny features the site does not use, e.g. 'camera=(), microphone=(), geolocation=()'.
- **Reference:** OWASP Secure Headers Project

## Scope and method

Only targets the operator is authorized to test were contacted. Checks are passive: ordinary HTTP GET/OPTIONS requests, no payloads, no authentication attempts, no writes. Severity reflects the weakness observed in this configuration, not a confirmed exploitation.

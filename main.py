"""
main.py — Entry point for the XSS Tester.

Sets up the CLI, configures logging, builds the Playwright browser context
with optional proxy / auth / storage-state, then orchestrates the spider
and XSS tester.  Handles SIGINT gracefully by saving partial findings.

Usage::

    python main.py --base-url https://target.com [options]

See ``python main.py --help`` or README.md for full documentation.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from playwright.async_api import Browser, BrowserContext, async_playwright

from Auth import AuthManager
from Reporter import Reporter
from Spider import Spider
from Tester import XSSTester

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="xss-tester",
        description="Async XSS testing tool powered by Playwright",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples
────────
  Basic scan:
    python main.py --base-url https://target.com

  With form authentication:
    python main.py --base-url https://target.com --auth-script auth.json

  With Burp Suite proxy (no-verify):
    python main.py --base-url https://target.com --proxy http://127.0.0.1:8080

  With custom CA certificate (cleaner TLS; install CA to system trust store first):
    python main.py --base-url https://target.com \
                   --proxy http://127.0.0.1:8080 \
                   --proxy-ca ~/burp_ca.der

  Full example:
    python main.py --base-url https://target.com \
                   --auth-script auth.json \
                   --proxy http://127.0.0.1:8080 \
                   --interactsh-url https://abc.interactsh.com \
                   --max-pages 200 --max-depth 5 \
                   --delay 0.5 --concurrency 5 \
                   --output findings.json \
                   --scope /app/ \
                   --no-headless --verbose
        """,
    )

    # ── Target ────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--base-url",
        required=True,
        metavar="URL",
        help="Starting URL to crawl (required)",
    )
    parser.add_argument(
        "--scope",
        default=None,
        metavar="PATH",
        help="Optional path prefix to restrict crawling (e.g. /app/)",
    )

    # ── Authentication ────────────────────────────────────────────────────────
    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "--auth-script",
        metavar="FILE",
        help="Path to JSON auth-script file describing the login flow",
    )
    auth.add_argument(
        "--cookies",
        metavar="STRING",
        help="Raw cookie string to inject (e.g. 'session=abc; csrf=xyz')",
    )

    # ── Proxy ─────────────────────────────────────────────────────────────────
    proxy = parser.add_argument_group("proxy")
    proxy.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP proxy to route traffic through (e.g. http://127.0.0.1:8080)",
    )
    proxy.add_argument(
        "--proxy-ca",
        metavar="FILE",
        help=(
            "Path to custom CA certificate (.pem/.der).  "
            "NOTE: Playwright cannot inject CA certs directly into Chromium; "
            "install the cert to your system trust store for strict TLS, "
            "otherwise TLS errors are suppressed with ignore_https_errors."
        ),
    )

    # ── Detection ─────────────────────────────────────────────────────────────
    detect = parser.add_argument_group("detection")
    detect.add_argument(
        "--interactsh-url",
        metavar="URL",
        help="Interactsh server URL for out-of-band (OOB) XSS detection",
    )
    detect.add_argument(
        "--payloads",
        default="payloads.txt",
        metavar="FILE",
        help="Path to newline-delimited XSS payload file (default: payloads.txt)",
    )
    detect.add_argument(
        "--oob-wait",
        type=float,
        default=15.0,
        metavar="SECS",
        help=(
            "Seconds to wait after all injections before polling interactsh "
            "for OOB callbacks (default: 15)"
        ),
    )
    detect.add_argument(
        "--disable-detection",
        dest="disabled_detections",
        nargs="+",
        metavar="METHOD",
        choices=["alert-dialog", "dom-mutation", "interactsh-oob"],
        default=[],
        help=(
            "Disable one or more detection methods. "
            "Choices: alert-dialog, dom-mutation, interactsh-oob. "
            "Example: --disable-detection alert-dialog dom-mutation"
        ),
    )
    detect.add_argument(
        "--re-crawl",
        action="store_true",
        default=False,
        help=(
            "After injection, re-visit every crawled page to detect stored XSS. "
            "Runs concurrently with the OOB wait period."
        ),
    )
    detect.add_argument(
        "--get-params-only",
        action="store_true",
        default=False,
        help="Only test URL GET parameters — skip all form input injection.",
    )

    # ── Crawl limits ──────────────────────────────────────────────────────────
    limits = parser.add_argument_group("crawl limits")
    limits.add_argument(
        "--max-pages",
        type=int,
        default=100,
        metavar="N",
        help="Maximum pages to crawl (default: 100)",
    )
    limits.add_argument(
        "--max-depth",
        type=int,
        default=3,
        metavar="N",
        help="Maximum BFS crawl depth (default: 3)",
    )
    limits.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECS",
        help="Delay in seconds between requests (default: 0)",
    )
    limits.add_argument(
        "--concurrency",
        type=int,
        default=3,
        metavar="N",
        help="Max concurrent browser pages (default: 3)",
    )

    # ── Output ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("output")
    out.add_argument(
        "--output",
        default="findings.json",
        metavar="FILE",
        help="JSON report output path (default: findings.json)",
    )
    out.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging",
    )

    # ── Browser ───────────────────────────────────────────────────────────────
    browser = parser.add_argument_group("browser")
    headless = browser.add_mutually_exclusive_group()
    headless.add_argument(
        "--headless",
        dest="headless",
        action="store_true",
        default=True,
        help="Run browser headlessly (default)",
    )
    headless.add_argument(
        "--no-headless",
        dest="headless",
        action="store_false",
        help="Show the browser UI (useful for debugging)",
    )

    return parser


# ---------------------------------------------------------------------------
# Browser context factory
# ---------------------------------------------------------------------------


async def _build_context(
    browser: Browser,
    args: argparse.Namespace,
) -> BrowserContext:
    """Create a Playwright :class:`BrowserContext` honouring all CLI options.

    Applies proxy settings, TLS configuration, and restores a previously
    saved storage state (written by :class:`~auth.AuthManager`) when available.
    """
    kwargs: dict = {}

    # ── Proxy ─────────────────────────────────────────────────────────────────
    if args.proxy:
        kwargs["proxy"] = {"server": args.proxy}
        if args.proxy_ca:
            logger.info(
                "Custom CA file provided (%s).  "
                "Playwright cannot inject CA certs directly into Chromium — "
                "TLS errors will be suppressed via ignore_https_errors.  "
                "For strict TLS, install the cert to your system trust store.",
                args.proxy_ca,
            )
        # Always disable TLS verification when a proxy is active so that
        # intercepting proxies (Burp, mitmproxy, etc.) don't break the scan.
        kwargs["ignore_https_errors"] = True

    # ── Storage state (persisted auth session) ────────────────────────────────
    state_file = Path(AuthManager.STATE_FILE)
    if state_file.exists():
        kwargs["storage_state"] = str(state_file)
        logger.debug("Restoring storage state from %s", state_file)

    return await browser.new_context(**kwargs)


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------


async def run(args: argparse.Namespace) -> None:
    """Orchestrate authentication, crawling, testing, and reporting."""
    reporter = Reporter(output_file=args.output)
    reporter.print_banner()

    shutdown_event = asyncio.Event()

    # ── SIGINT handler ────────────────────────────────────────────────────────
    def _on_sigint(*_) -> None:
        reporter.log_info(
            "[yellow]Ctrl-C received — saving partial findings and exiting…[/yellow]"
        )
        shutdown_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    # ── Auth manager ──────────────────────────────────────────────────────────
    auth_manager = AuthManager(
        auth_script=args.auth_script,
        cookies_str=args.cookies,
    )

    # ── Semaphore for concurrency control ─────────────────────────────────────
    semaphore = asyncio.Semaphore(args.concurrency)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=args.headless)

        # ── Step 1: authenticate in a temporary context ───────────────────────
        if auth_manager.has_auth():
            if args.auth_script:
                reporter.log_info(f"Authentication:      [bold cyan]Script ({args.auth_script})[/bold cyan]")
            elif args.cookies:
                reporter.log_info("Authentication:      [bold cyan]Cookies[/bold cyan]")
        
            auth_ctx_kwargs: dict = {}
            if args.proxy:
                auth_ctx_kwargs["proxy"] = {"server": args.proxy}
                auth_ctx_kwargs["ignore_https_errors"] = True

            auth_ctx = await browser.new_context(**auth_ctx_kwargs)
            try:
                await auth_manager.authenticate(auth_ctx, args.base_url)
            finally:
                await auth_ctx.close()
        else:
            reporter.log_info("Authentication:      [yellow]None[/yellow]")


        # ── Step 2: main context (reuses saved storage state) ─────────────────
        context = await _build_context(browser, args)

        reporter.log_info(f"Target:      [bold cyan]{args.base_url}[/bold cyan]")
        reporter.log_info(f"Max pages:   {args.max_pages}   depth: {args.max_depth}")
        reporter.log_info(f"Concurrency: {args.concurrency}   delay: {args.delay}s")
        if args.scope:
            reporter.log_info(f"Scope:       {args.scope}")
        if args.proxy:
            reporter.log_info(f"Proxy:       {args.proxy}")
        if args.interactsh_url:
            reporter.log_info(f"Interactsh:  {args.interactsh_url}")
        if args.disabled_detections:
            reporter.log_info(
                f"Disabled:    [yellow]{', '.join(sorted(args.disabled_detections))}[/yellow]"
            )
        if args.get_params_only:
            reporter.log_info("Mode:        [yellow]GET params only[/yellow]")

        # ── Step 3: crawl ─────────────────────────────────────────────────────
        spider = Spider(
            context=context,
            base_url=args.base_url,
            scope=args.scope,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            delay=args.delay,
            semaphore=semaphore,
            auth_manager=auth_manager,
            reporter=reporter,
            shutdown_event=shutdown_event,
        )

        pages = await spider.crawl()
        reporter.log_info(
            f"Crawl complete — [bold]{len(pages)}[/bold] pages discovered."
        )

        # ── Step 4: test ──────────────────────────────────────────────────────
        if not shutdown_event.is_set() and pages:
            tester = XSSTester(
                context=context,
                payloads_file=args.payloads,
                reporter=reporter,
                delay=args.delay,
                semaphore=semaphore,
                auth_manager=auth_manager,
                interactsh_url=args.interactsh_url,
                shutdown_event=shutdown_event,
                disabled_detections=set(args.disabled_detections),
                oob_wait=args.oob_wait,
                get_params_only=args.get_params_only,
            )
            await tester.test_all(pages)

            # Re-crawl runs during the OOB wait period — productive use of
            # the delay rather than dead time.
            if args.re_crawl and not shutdown_event.is_set():
                await tester.re_crawl(pages)

            # Wait for the background OOB sweep thread (no-op if OOB not active).
            # Must finish before the browser context closes and before the report
            # is saved so that OOB findings are included in the output.
            await tester.join_oob_thread()
        elif not pages:
            reporter.log_error(
                "No pages discovered — check --base-url, --scope, and auth settings."
            )

        try:
            await context.close()
        except Exception:
            pass
        try:
            await browser.close()
        except Exception:
            pass

    # ── Persist and summarise ─────────────────────────────────────────────────
    reporter.save()
    reporter.print_summary()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse arguments, configure logging, and run the async main loop."""
    parser = build_arg_parser()
    args = parser.parse_args()

    # ── Logging setup ─────────────────────────────────────────────────────────
    log_level = logging.DEBUG if args.verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    # Suppress noisy library logs unless in verbose mode
    if not args.verbose:
        for lib in ("playwright", "httpx", "asyncio"):
            logging.getLogger(lib).setLevel(logging.WARNING)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        # Second Ctrl-C while cleanup is running — exit immediately
        sys.exit(0)


if __name__ == "__main__":
    main()

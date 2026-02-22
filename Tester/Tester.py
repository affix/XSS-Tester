"""
Tester/Tester.py — XSS payload injection and multi-method detection.

Detection methods:
  1. ``alert-dialog``   — ``page.on('dialog')`` fires when the browser shows an alert.
  2. ``dom-mutation``   — After injection we evaluate ``window.__xss === true``; payloads
                         that set that global flag (e.g. onerror/onload handlers) are caught
                         here without producing a visible dialog.
  3. ``interactsh-oob`` — Each injection uses a unique subdomain on the interactsh server;
                         after testing we poll for callbacks from the server.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import threading
import time
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from playwright.async_api import (
    BrowserContext,
    Dialog,
    Error as PlaywrightError,
    Page,
)

from Auth import AuthManager
from Interactsh import InteractshClient
from Models import Finding, InputField, PageData, UrlParam
from Reporter import Reporter

logger = logging.getLogger(__name__)

# Placeholder substituted into OOB payloads with the per-test interactsh host
_OOB_HOST_PLACEHOLDER = "INTERACTSH_HOST"


# ---------------------------------------------------------------------------
# XSS Tester
# ---------------------------------------------------------------------------


class XSSTester:
    """Injects XSS payloads into discovered inputs and detects execution.

    Concurrency is controlled by *semaphore*; each individual injection
    acquires the semaphore before opening a new browser page.
    """

    #: All valid detection method names.
    DETECTION_METHODS: frozenset[str] = frozenset(
        {"alert-dialog", "dom-mutation", "interactsh-oob"}
    )

    def __init__(
        self,
        context: BrowserContext,
        payloads_file: str,
        reporter: Reporter,
        delay: float,
        semaphore: asyncio.Semaphore,
        auth_manager: AuthManager,
        interactsh_url: Optional[str],
        shutdown_event: asyncio.Event,
        disabled_detections: Optional[set[str]] = None,
        oob_wait: float = 15.0,
        get_params_only: bool = False,
    ) -> None:
        self.context = context
        self.payloads_file = payloads_file
        self.reporter = reporter
        self.delay = delay
        self.semaphore = semaphore
        self.auth_manager = auth_manager
        self.interactsh_url = interactsh_url
        self.shutdown_event = shutdown_event
        self._disabled: frozenset[str] = frozenset(disabled_detections or ())
        self._oob_wait = oob_wait
        self._get_params_only = get_params_only

        self._payloads: list[str] = []
        self._interactsh: Optional[InteractshClient] = None
        # Tracks (test_id, page_url, param_label, payload) for every OOB injection
        self._oob_pending: list[tuple[str, str, str, str]] = []
        # Background thread that runs the OOB wait + poll
        self._oob_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def test_all(self, pages: list[PageData]) -> None:
        """Run all XSS tests for every page in *pages*.

        Builds a flat list of (injection coroutine) tasks, then schedules them
        via :func:`asyncio.gather`. Concurrency is gated inside each task by
        the shared semaphore.
        """
        self._load_payloads()
        if not self._payloads:
            self.reporter.log_error("No payloads loaded — skipping XSS tests.")
            return

        if self.interactsh_url:
            self._interactsh = InteractshClient(self.interactsh_url)
            await self._interactsh.register()

        # Build every injection task upfront
        _alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

        def _new_test_id() -> str:
            # Must be <= InteractshClient.NONCE_LENGTH (13) lowercase alphanumeric chars
            return "".join(secrets.choice(_alphabet) for _ in range(13))

        tasks: list[asyncio.Task] = []
        for page_data in pages:
            if not self._get_params_only:
                for inp in page_data.inputs:
                    for payload in self._payloads:
                        test_id = _new_test_id()
                        self.reporter.inputs_tested += 1
                        tasks.append(
                            asyncio.ensure_future(
                                self._inject_into_input(
                                    page_url=page_data.url,
                                    inp=inp,
                                    payload=payload,
                                    test_id=test_id,
                                )
                            )
                        )

            for url_param in page_data.url_params:
                for payload in self._payloads:
                    test_id = _new_test_id()
                    self.reporter.inputs_tested += 1
                    tasks.append(
                        asyncio.ensure_future(
                            self._inject_into_url_param(
                                url_param=url_param,
                                payload=payload,
                                test_id=test_id,
                            )
                        )
                    )

        self.reporter.log_info(
            f"Testing [bold]{len(tasks)}[/bold] injection points "
            f"([yellow]{len(self._payloads)}[/yellow] payloads × inputs)…"
        )

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

        # Launch the OOB sweep in a background thread so the event loop stays
        # responsive during the wait period.  Call join_oob_thread() afterwards
        # to wait for results and close the interactsh client.
        if (
            self._oob_pending
            and self._interactsh
            and "interactsh-oob" not in self._disabled
            and not self.shutdown_event.is_set()
        ):
            loop = asyncio.get_running_loop()
            self._oob_thread = threading.Thread(
                target=self._oob_thread_worker,
                args=(loop,),
                daemon=True,
                name="oob-sweep",
            )
            self._oob_thread.start()

    # ------------------------------------------------------------------
    # Form-input injection
    # ------------------------------------------------------------------

    async def _inject_into_input(
        self,
        page_url: str,
        inp: InputField,
        payload: str,
        test_id: str,
    ) -> None:
        """Inject *payload* into *inp* on *page_url* and check for XSS."""
        if self.shutdown_event.is_set():
            return

        # Resolve OOB payload if interactsh is active
        effective_payload = self._resolve_oob_payload(payload, test_id)

        # Record for the post-scan OOB sweep
        if _OOB_HOST_PLACEHOLDER in payload and self._interactsh and self._interactsh._registered:
            self._oob_pending.append(
                (test_id, page_url, inp.name or inp.selector, effective_payload)
            )

        async with self.semaphore:
            await self._do_input_injection(
                page_url=page_url,
                inp=inp,
                payload=effective_payload,
                test_id=test_id,
                param_label=inp.name or inp.selector,
            )

        if self.delay:
            await asyncio.sleep(self.delay)

    async def _do_input_injection(
        self,
        page_url: str,
        inp: InputField,
        payload: str,
        test_id: str,
        param_label: str,
    ) -> None:
        """Open a page, fill the input, submit if in a form, and detect XSS."""
        page: Optional[Page] = None
        dialog_triggered = False

        try:
            page = await self.context.new_page()

            async def _on_dialog(dialog: Dialog) -> None:
                nonlocal dialog_triggered
                dialog_triggered = True
                logger.debug("Dialog fired on %s (id=%s)", page_url, test_id)
                await dialog.dismiss()

            page.on("dialog", _on_dialog)

            # Navigate
            await page.goto(page_url, wait_until="networkidle", timeout=30_000)

            # Re-auth if redirected to login
            if self.auth_manager.is_login_page(page.url):
                await page.close()
                page = None
                await self.auth_manager.re_authenticate(self.context)
                page = await self.context.new_page()
                page.on("dialog", _on_dialog)
                await page.goto(page_url, wait_until="networkidle", timeout=30_000)

            # Trigger layout recalculation for Dojo BorderContainer / ContentPane
            # widgets.  They calculate pane sizes on window resize events; without
            # one, buttons inside nested panes remain invisible and unclickable
            # even though their DOM nodes exist.  Also call each widget's resize()
            # directly as belt-and-suspenders.
            await self._trigger_layout(page)

            # Reveal content hidden behind tab panels before locating the input.
            await self._reveal_element(page, inp.selector)

            # Locate input
            try:
                element = await page.wait_for_selector(inp.selector, timeout=5_000)
            except PlaywrightError:
                logger.debug("Selector not found on page: %s", inp.selector)
                return

            if not element:
                return

            # Fill input with payload.
            # Guard against elements that became non-editable after page load
            # (e.g. Dojo widget internals that were not filtered at crawl time).
            try:
                if not await element.is_editable():
                    logger.debug("Input not editable, skipping: %s", inp.selector)
                    return
            except PlaywrightError:
                return

            # Capture the current value so it can be restored if client-side
            # validation rejects the payload (aria-invalid → "true").
            try:
                prev_val = await element.evaluate("el => el.value")
            except PlaywrightError:
                prev_val = ""

            try:
                await element.fill(payload, timeout=5_000)
            except PlaywrightError as exc:
                logger.debug("Could not fill %s: %s", inp.selector, exc)
                return

            # If client-side validation fires and marks the field invalid the
            # server will never see the payload — restore the original value
            # and skip this injection.
            try:
                if await element.get_attribute("aria-invalid") == "true":
                    logger.debug("aria-invalid after fill — restoring and skipping: %s", inp.selector)
                    try:
                        await element.fill(prev_val, timeout=3_000)
                    except PlaywrightError:
                        pass
                    return
            except PlaywrightError:
                pass

            # Fill sibling inputs with dummy values to avoid validation errors
            if inp.form_selector:
                await self._fill_sibling_inputs(page, inp)

            # Submit: press Enter on the filled field, then also click the first
            # Save/Submit button found via text search.  Both run unconditionally
            # so whichever the app responds to will trigger the submission.
            try:
                await element.press("Enter")
            except PlaywrightError:
                pass

            try:
                clicked = await page.evaluate("""
                    () => {
                        const kw = /\\b(save|submit|ok|apply|confirm|update|create|add)\\b/i;
                        const walker = document.createTreeWalker(
                            document.body, NodeFilter.SHOW_TEXT, null
                        );
                        let node;
                        while ((node = walker.nextNode())) {
                            const text = node.textContent.trim();
                            if (text.length > 0 && text.length < 50 && kw.test(text)) {
                                node.parentElement.click();
                                return text;
                            }
                        }
                        return null;
                    }
                """)
                logger.debug("Text-based submit click: %s", clicked or "no match")
            except PlaywrightError as exc:
                logger.debug("Submit JS click failed: %s", exc)

            # Always wait for network idle regardless of which submit path ran.
            try:
                await page.wait_for_load_state("networkidle", timeout=10_000)
            except PlaywrightError:
                pass

            detection = await self._detect(page, dialog_triggered, test_id)
            if detection:
                self.reporter.log_finding(
                    Finding(
                        url=page_url,
                        parameter=param_label,
                        payload=payload,
                        detection_method=detection,
                        test_id=test_id,
                    )
                )

        except PlaywrightError as exc:
            logger.debug("Playwright error in input injection (%s): %s", test_id, exc)
        except Exception as exc:
            logger.debug("Unexpected error in input injection (%s): %s", test_id, exc)
        finally:
            if page and not page.is_closed():
                try:
                    await page.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # URL-parameter injection
    # ------------------------------------------------------------------

    async def _inject_into_url_param(
        self,
        url_param: UrlParam,
        payload: str,
        test_id: str,
    ) -> None:
        """Inject *payload* into a URL parameter and check for XSS."""
        if self.shutdown_event.is_set():
            return

        effective_payload = self._resolve_oob_payload(payload, test_id)
        injected_url = self._build_injected_url(url_param, effective_payload)

        # Record for the post-scan OOB sweep
        if _OOB_HOST_PLACEHOLDER in payload and self._interactsh and self._interactsh._registered:
            self._oob_pending.append(
                (test_id, url_param.url, f"?{url_param.param_name}", effective_payload)
            )

        async with self.semaphore:
            await self._do_url_injection(
                injected_url=injected_url,
                original_url=url_param.url,
                param_label=f"?{url_param.param_name}",
                payload=effective_payload,
                test_id=test_id,
            )

        if self.delay:
            await asyncio.sleep(self.delay)

    async def _do_url_injection(
        self,
        injected_url: str,
        original_url: str,
        param_label: str,
        payload: str,
        test_id: str,
    ) -> None:
        """Navigate to the injected URL and detect XSS."""
        page: Optional[Page] = None
        dialog_triggered = False

        try:
            page = await self.context.new_page()

            async def _on_dialog(dialog: Dialog) -> None:
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()

            page.on("dialog", _on_dialog)

            await page.goto(injected_url, wait_until="networkidle", timeout=30_000)

            # Re-auth if redirected
            if self.auth_manager.is_login_page(page.url):
                await page.close()
                page = None
                await self.auth_manager.re_authenticate(self.context)
                page = await self.context.new_page()
                page.on("dialog", _on_dialog)
                await page.goto(injected_url, wait_until="networkidle", timeout=30_000)

            detection = await self._detect(page, dialog_triggered, test_id)
            if detection:
                self.reporter.log_finding(
                    Finding(
                        url=original_url,
                        parameter=param_label,
                        payload=payload,
                        detection_method=detection,
                        test_id=test_id,
                    )
                )

        except PlaywrightError as exc:
            logger.debug("Playwright error in URL injection (%s): %s", test_id, exc)
        except Exception as exc:
            logger.debug("Unexpected error in URL injection (%s): %s", test_id, exc)
        finally:
            if page and not page.is_closed():
                try:
                    await page.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    async def _detect(
        self,
        page: Page,
        dialog_triggered: bool,
        test_id: str,
    ) -> Optional[str]:
        """Run enabled detection checks and return the method name or *None*.

        Priority: alert-dialog > dom-mutation > interactsh-oob.
        Individual methods can be skipped via ``--disable-detection``.
        """
        # Method 1: alert dialog
        if "alert-dialog" not in self._disabled and dialog_triggered:
            return "alert-dialog"

        # Method 2: DOM mutation (window.__xss === true)
        if "dom-mutation" not in self._disabled:
            try:
                xss_set: bool = await page.evaluate("() => window.__xss === true")
                if xss_set:
                    return "dom-mutation"
            except PlaywrightError:
                pass

        return None

    async def re_crawl(self, pages: list[PageData]) -> None:
        """Visit all previously crawled pages to detect stored XSS.

        Called after :meth:`test_all` so that payloads injected during the
        test phase have been persisted server-side.  Each page is visited once
        without any injection; XSS execution is detected via the same
        ``alert-dialog`` and ``dom-mutation`` methods used during injection
        testing.  Findings are tagged ``stored:<method>`` to distinguish them
        from reflected XSS findings.

        This runs concurrently with the background OOB sweep thread, making
        productive use of the ``--oob-wait`` period.
        """
        if self.shutdown_event.is_set() or not pages:
            return

        self.reporter.log_info(
            f"Re-crawl: checking [bold]{len(pages)}[/bold] pages for stored XSS…"
        )

        tasks = [
            asyncio.ensure_future(self._visit_for_stored_xss(page_data.url))
            for page_data in pages
        ]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

        self.reporter.log_info("Re-crawl complete.")

    async def _visit_for_stored_xss(self, url: str) -> None:
        """Navigate to *url* without injecting and check for XSS execution."""
        if self.shutdown_event.is_set():
            return

        async with self.semaphore:
            page: Optional[Page] = None
            dialog_triggered = False

            try:
                page = await self.context.new_page()

                async def _on_dialog(dialog: Dialog) -> None:
                    nonlocal dialog_triggered
                    dialog_triggered = True
                    await dialog.dismiss()

                page.on("dialog", _on_dialog)
                await page.goto(url, wait_until="networkidle", timeout=30_000)

                if self.auth_manager.is_login_page(page.url):
                    await page.close()
                    page = None
                    await self.auth_manager.re_authenticate(self.context)
                    page = await self.context.new_page()
                    page.on("dialog", _on_dialog)
                    await page.goto(url, wait_until="networkidle", timeout=30_000)

                detection = await self._detect(page, dialog_triggered, "")
                if detection:
                    test_id = "".join(
                        secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                        for _ in range(13)
                    )
                    self.reporter.log_finding(
                        Finding(
                            url=url,
                            parameter="(stored)",
                            payload="(stored — injected during test phase)",
                            detection_method=f"stored:{detection}",
                            test_id=test_id,
                        )
                    )

            except PlaywrightError as exc:
                logger.debug("Playwright error during re-crawl of %s: %s", url, exc)
            except Exception as exc:
                logger.debug("Unexpected error during re-crawl of %s: %s", url, exc)
            finally:
                if page and not page.is_closed():
                    try:
                        await page.close()
                    except Exception:
                        pass

        if self.delay:
            await asyncio.sleep(self.delay)

    async def join_oob_thread(self) -> None:
        """Wait for the background OOB sweep thread to finish, then close the client.

        Must be called after :meth:`test_all` when OOB detection is enabled.
        Awaiting this coroutine does not block the event loop — the join runs
        in a worker thread via :func:`asyncio.to_thread`.
        """
        if self._oob_thread is not None:
            await asyncio.to_thread(self._oob_thread.join)
        if self._interactsh:
            await self._interactsh.aclose()

    def _oob_thread_worker(self, loop: asyncio.AbstractEventLoop) -> None:
        """Background thread: sleep, poll interactsh, then report any matches.

        The sleep is broken into 0.5 s intervals so that a shutdown request
        (SIGINT setting :attr:`shutdown_event`) can abort the wait early.
        The async :meth:`~InteractshClient.poll` call is dispatched back onto
        the running event loop via :func:`asyncio.run_coroutine_threadsafe` so
        the single ``httpx.AsyncClient`` is only ever used from one thread.
        """
        n = len(self._oob_pending)
        self.reporter.log_info(
            f"OOB sweep: waiting [bold]{self._oob_wait:.0f}s[/bold] "
            f"for {n} pending callback(s)…"
        )

        # Interruptible sleep — abort early on shutdown
        deadline = time.monotonic() + self._oob_wait
        while time.monotonic() < deadline:
            if self.shutdown_event.is_set():
                logger.debug("OOB sweep: shutdown requested — aborting wait")
                return
            time.sleep(min(0.5, deadline - time.monotonic()))

        if self.shutdown_event.is_set():
            return

        # Schedule the async poll on the main event loop and block until done
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._interactsh.poll(), loop
            )
            interactions = future.result(timeout=30)
        except Exception as exc:
            logger.debug("OOB poll error: %s", exc)
            return

        if not interactions:
            logger.debug("OOB sweep: no interactions received")
            return

        logger.debug("OOB sweep: received %d interaction(s)", len(interactions))
        for ia in interactions:
            logger.debug(
                "Interaction: proto=%s unique-id=%s",
                ia.get("protocol"), ia.get("unique-id"),
            )

        for test_id, url, param, payload in self._oob_pending:
            nonce = self._interactsh.interaction_test_id(test_id)
            # unique-id is the full first label (corr_id + nonce), so check endswith
            if any(ia.get("unique-id", "").endswith(nonce) for ia in interactions):
                self.reporter.log_finding(
                    Finding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        detection_method="interactsh-oob",
                        test_id=test_id,
                    )
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_payloads(self) -> None:
        """Read XSS payloads from :attr:`payloads_file`, skipping comments/blanks."""
        try:
            with open(self.payloads_file) as fh:
                self._payloads = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.lstrip().startswith("#")
                ]
            logger.info(
                "Loaded %d payloads from %s", len(self._payloads), self.payloads_file
            )
        except FileNotFoundError:
            logger.error("Payloads file not found: %s", self.payloads_file)
            self._payloads = []

    def _resolve_oob_payload(self, payload: str, test_id: str) -> str:
        """Replace :data:`_OOB_HOST_PLACEHOLDER` in *payload* with the live host.

        If interactsh is not registered the placeholder is replaced with an
        empty string (neutralising the OOB portion of hybrid payloads).
        """
        if _OOB_HOST_PLACEHOLDER not in payload:
            return payload
        if self._interactsh:
            host = self._interactsh.interaction_host(test_id)
            return payload.replace(_OOB_HOST_PLACEHOLDER, host)
        return payload.replace(_OOB_HOST_PLACEHOLDER, "")

    def _build_injected_url(self, url_param: UrlParam, payload: str) -> str:
        """Return the URL with *url_param.param_name* replaced by *payload*."""
        parsed = urlparse(url_param.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[url_param.param_name] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def _find_submit_button(self, page: Page, form_selector: Optional[str]):
        """Return a clickable submit button, or *None*.

        Search order:

        1. Standard ``[type=submit]`` / ``button[type=submit]`` / typeless
           ``<button>`` **inside** the form (skipped when *form_selector* is
           ``None``).
        2. Dojo ``dijitButton`` widgets **inside** the form — these render as
           ``<span role="button">`` (not ``<button type="submit">``), so they
           are invisible to selector 1.  Also skipped when no form.
        3. Page-wide keyword search across all interactive elements whose
           visible text contains a submit-indicating word: ``save``,
           ``submit``, ``ok``, ``apply``, ``confirm``, ``update``, ``create``,
           ``add``.  This is the primary path for Dojo apps where action
           buttons live in a separate ``ContentPane`` outside ``<form>``.
        """
        # 1 & 2 — within the form (only when a form selector is known)
        if form_selector:
            within_form = [
                f"{form_selector} [type=submit]",
                f"{form_selector} button[type=submit]",
                f"{form_selector} button:not([type])",
                # Dojo: clickable span with role="button" inside .dijitButtonNode
                f"{form_selector} .dijitButtonContents[role='button']",
                f"{form_selector} .dijitButtonNode",
                f"{form_selector} .dijitButton button",
            ]
            for sel in within_form:
                try:
                    el = await page.query_selector(sel)
                    if el:
                        return el
                except PlaywrightError:
                    continue

        # 3 — page-wide keyword search
        # Includes Dojo's span[role='button'] (.dijitButtonContents) which is the
        # actual interactive target — not the hidden dijitOffScreen <input>.
        _keywords = {"save", "submit", "ok", "apply", "confirm", "update", "create", "add"}
        candidates_sel = (
            "button, input[type=submit], "
            "[role='button']:not([aria-disabled='true']), "
            ".dijitButtonNode"
        )
        try:
            candidates = await page.query_selector_all(candidates_sel)
            for el in candidates:
                try:
                    text = ((await el.text_content()) or "").strip().lower()
                    val = (await el.get_attribute("value") or "").strip().lower()
                    if any(kw in text or kw in val for kw in _keywords):
                        return el
                except PlaywrightError:
                    continue
        except PlaywrightError:
            pass

        return None

    async def _trigger_layout(self, page: Page) -> None:
        """Fire a window resize event and call each Dojo widget's resize().

        Dojo layout widgets (BorderContainer, ContentPane, TabContainer, …)
        calculate their dimensions lazily on ``window.resize``.  Playwright
        opens a fixed viewport and never fires one, so nested panes — and the
        action buttons inside them — stay invisible until a resize occurs.
        Dispatching the event here replicates what a manual browser resize does.
        """
        try:
            await page.evaluate("""
                () => {
                    window.dispatchEvent(new Event('resize'));
                    if (window.dijit && window.dijit.registry) {
                        window.dijit.registry.forEach(w => {
                            if (typeof w.resize === 'function') {
                                try { w.resize(); } catch (_) {}
                            }
                        });
                    }
                }
            """)
            await page.wait_for_timeout(300)
        except PlaywrightError:
            pass

    async def _reveal_element(self, page: Page, selector: str) -> None:
        """Click tabs one at a time until *selector* is visible on the page.

        Dojo (and other widget frameworks) keep hidden tab-panel content in
        the DOM but set ``display:none`` on inactive panels.
        ``query_selector`` finds such elements immediately, but they cannot
        be filled until their panel is active.  We therefore check
        ``is_visible()`` — not just DOM presence — and only stop clicking
        once the element is truly accessible.

        Stops as soon as the target is visible so the correct tab stays
        active for filling and submission.
        """
        # Check whether the element is already visible.
        try:
            el = await page.query_selector(selector)
            if el and await el.is_visible():
                return
        except PlaywrightError:
            return  # Can't inspect — skip tab revelation.

        tab_selectors = [
            "[role='tablist'] [role='tab']",
            "[role='tab']",
        ]
        clicked: set[str] = set()

        for sel in tab_selectors:
            try:
                tabs = await page.query_selector_all(sel)
            except PlaywrightError as exc:
                logger.debug("Tab query for '%s' failed: %s", sel, exc)
                continue

            for tab in tabs:
                try:
                    label = ((await tab.text_content()) or "").strip()[:80]
                    if label in clicked:
                        continue
                    clicked.add(label)
                    await tab.evaluate("el => el.click()")
                    await page.wait_for_timeout(300)
                    # Stop only once the element is actually visible.
                    el = await page.query_selector(selector)
                    if el and await el.is_visible():
                        return
                except PlaywrightError as exc:
                    logger.debug("Error clicking tab '%s': %s", label, exc)

    async def _fill_sibling_inputs(self, page: Page, skip: InputField) -> None:
        """Fill all other inputs within the same form with a dummy value.

        Runs entirely inside a single ``page.evaluate`` call so there is no
        per-element Playwright IPC overhead.  All filtering (disabled, readonly,
        ARIA-managed, combobox ancestry) and aria-invalid restore logic happen
        in the browser process and complete in one round-trip.
        """
        if not skip.form_selector:
            return
        try:
            await page.evaluate(
                """
                ([formSel, skipSel]) => {
                    const form = document.querySelector(formSel);
                    if (!form) return;

                    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
                    const rand = () => Array.from(
                        {length: 8},
                        () => chars[Math.floor(Math.random() * chars.length)]
                    ).join('');

                    const fields = form.querySelectorAll(
                        'input:not([type=submit]):not([type=button])' +
                        ':not([type=reset]):not([type=hidden]):not([type=file]),' +
                        'textarea'
                    );

                    fields.forEach(el => {
                        // Skip the field we already filled with the payload.
                        try { if (el.matches(skipSel)) return; } catch (_) {}

                        // Skip disabled / readonly elements.
                        if (el.disabled || el.readOnly) return;

                        // Skip ARIA-managed / combobox inputs.
                        if (el.hasAttribute('aria-autocomplete')) return;
                        if (el.hasAttribute('aria-haspopup'))     return;
                        if (el.hasAttribute('aria-invalid'))      return;

                        // Skip inputs inside a combobox / listbox ancestor.
                        let p = el.parentElement;
                        while (p) {
                            const r = p.getAttribute('role');
                            if (r === 'combobox' || r === 'listbox') return;
                            p = p.parentElement;
                        }

                        const prev = el.value;
                        el.value = rand();
                        el.dispatchEvent(new Event('input',  {bubbles: true}));
                        el.dispatchEvent(new Event('change', {bubbles: true}));

                        // If validation rejected the dummy value restore original.
                        if (el.getAttribute('aria-invalid') === 'true') {
                            el.value = prev;
                            el.dispatchEvent(new Event('input',  {bubbles: true}));
                            el.dispatchEvent(new Event('change', {bubbles: true}));
                        }
                    });
                }
                """,
                [skip.form_selector, skip.selector],
            )
        except PlaywrightError as exc:
            logger.debug("Error filling sibling inputs: %s", exc)

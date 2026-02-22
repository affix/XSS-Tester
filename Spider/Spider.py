"""
Spider/Spider.py — Async web crawler and input-discovery engine.

Crawls from a base URL, stays within the target domain and optional scope
path, waits for SPA network-idle states, and extracts:
  - All HTML form inputs and standalone inputs
  - URL parameters present in the page URL
  - Outgoing links for further crawling, including links hidden inside
    JavaScript-driven dropdown menus (Dojo dijit/MenuBar, ARIA menus, etc.)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    parse_qs,
    urlencode,
)

from playwright.async_api import BrowserContext, Error as PlaywrightError, Page

from Auth import AuthManager
from Models import InputField, PageData, UrlParam
from Reporter import Reporter

logger = logging.getLogger(__name__)

# File extensions that will never contain HTML worth testing
_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".svg", ".ico", ".css", ".js", ".mjs", ".ts",
        ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
        ".exe", ".dmg", ".pkg", ".deb", ".rpm", ".msi",
        ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".webm",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".xml", ".json", ".csv", ".xls", ".xlsx", ".doc", ".docx",
        ".ppt", ".pptx",
    }
)


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------


class Spider:
    """Async BFS web crawler.

    Opens a new Playwright page for each URL, waits for ``networkidle``,
    then extracts inputs and links before closing the page. Respects the
    ``--max-pages`` and ``--max-depth`` limits. Concurrency is controlled
    by the shared :class:`asyncio.Semaphore`.
    """

    def __init__(
        self,
        context: BrowserContext,
        base_url: str,
        scope: Optional[str],
        max_pages: int,
        max_depth: int,
        delay: float,
        semaphore: asyncio.Semaphore,
        auth_manager: AuthManager,
        reporter: Reporter,
        shutdown_event: asyncio.Event,
    ) -> None:
        self.context = context
        self.base_url = base_url.rstrip("/")
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.semaphore = semaphore
        self.auth_manager = auth_manager
        self.reporter = reporter
        self.shutdown_event = shutdown_event

        parsed = urlparse(base_url)
        self.base_domain: str = parsed.netloc

        self._visited: set[str] = set()
        # Tracks (netloc, path, frozenset(param_names)) to avoid re-crawling
        # URLs that differ only in GET parameter values.
        self._visited_param_sigs: set[tuple] = set()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def crawl(self) -> list[PageData]:
        """Crawl from :attr:`base_url` and return discovered :class:`PageData`.

        Uses a level-by-level BFS where all URLs at the same depth are visited
        concurrently via :func:`asyncio.gather`. Concurrency is still bounded
        by the shared :class:`asyncio.Semaphore`. Crawl stops when the queue
        is empty, :attr:`max_pages` is reached, or a shutdown is requested.
        """
        current_batch: list[tuple[str, int]] = [(self.base_url, 0)]
        results: list[PageData] = []

        async def _bounded_visit(url: str, depth: int) -> Optional[PageData]:
            async with self.semaphore:
                return await self._visit_page(url, depth)

        while current_batch and not self.shutdown_event.is_set():
            # Deduplicate and filter the batch before dispatching
            to_visit: list[tuple[str, int]] = []
            for url, depth in current_batch:
                if len(self._visited) >= self.max_pages:
                    logger.info("max-pages limit (%d) reached", self.max_pages)
                    break
                norm_url = self._normalize_url(url)
                if not norm_url:
                    continue
                if norm_url in self._visited:
                    continue
                if not self._in_scope(norm_url):
                    continue
                if self._should_skip(norm_url):
                    continue
                param_sig = self._param_signature(norm_url)
                if param_sig in self._visited_param_sigs:
                    logger.debug("Skipping %s — same path+params already crawled", norm_url)
                    continue
                self._visited.add(norm_url)
                self._visited_param_sigs.add(param_sig)
                to_visit.append((norm_url, depth))

            if not to_visit:
                break

            # Visit the whole batch concurrently
            page_datas = await asyncio.gather(
                *[_bounded_visit(url, depth) for url, depth in to_visit],
                return_exceptions=True,
            )

            next_batch: list[tuple[str, int]] = []
            for (norm_url, depth), page_data in zip(to_visit, page_datas):
                if isinstance(page_data, Exception) or page_data is None:
                    continue

                # Mark the final (post-redirect) URL as visited so a direct
                # link to it doesn't cause it to be crawled again.
                norm_final = self._normalize_url(page_data.url)
                if norm_final and norm_final != norm_url:
                    self._visited.add(norm_final)

                results.append(page_data)
                self.reporter.pages_crawled += 1
                self.reporter.log_info(
                    f"Crawled [cyan]{page_data.url}[/cyan]  "
                    f"inputs=[yellow]{len(page_data.inputs)}[/yellow]  "
                    f"url-params=[yellow]{len(page_data.url_params)}[/yellow]  "
                    f"depth={depth}"
                )

                if depth < self.max_depth:
                    for link_url in page_data.links:
                        next_batch.append((link_url, depth + 1))

            current_batch = next_batch

            if self.delay:
                await asyncio.sleep(self.delay)

        return results

    # ------------------------------------------------------------------
    # Page visit
    # ------------------------------------------------------------------

    async def _visit_page(self, url: str, depth: int) -> Optional[PageData]:
        """Open *url* in a new page and extract all testable data.

        Returns *None* on navigation error or non-HTML response.
        """
        page: Optional[Page] = None
        try:
            page = await self.context.new_page()

            response = await page.goto(url, wait_until="networkidle", timeout=30_000)

            # Detect session expiry (redirect to login page)
            if self.auth_manager.is_login_page(page.url):
                logger.info("Session expiry detected at %s — re-authenticating", url)
                await page.close()
                page = None
                await self.auth_manager.re_authenticate(self.context)
                page = await self.context.new_page()
                response = await page.goto(url, wait_until="networkidle", timeout=30_000)

            # Skip non-successful responses
            if response and response.status >= 400:
                logger.debug("HTTP %d for %s — skipping", response.status, url)
                return None

            # Verify we got HTML (skip e.g. JSON API responses the spider stumbled on)
            content_type = ""
            if response:
                content_type = response.headers.get("content-type", "")
            if content_type and "html" not in content_type.lower() and not content_type == "":
                logger.debug("Non-HTML content-type '%s' for %s — skipping", content_type, url)
                return None

            browser_url = page.url

            # If the server redirected outside our target domain, skip
            if not self._in_scope(browser_url):
                logger.debug(
                    "Redirect left scope: %s -> %s — skipping", url, browser_url
                )
                return None

            # Decide the canonical URL for this page.
            #
            # Some apps (Dojo/Struts/.action frameworks) use a single catch-all
            # URL (e.g. IndexAction.action) for every view via server-side
            # forwarding. The browser URL changes path but stays on the same
            # scheme+host. Treating that as a real redirect would collapse every
            # distinct action URL into the same page_data entry, breaking both
            # deduplication and payload re-navigation.
            #
            # Rule: when the URL change is same-scheme + same-host (path only),
            # prefer the originally requested href as the page identity. Only
            # follow the browser URL when the scheme or host actually changes
            # (e.g. http→https upgrades, cross-domain redirects).
            if browser_url != url:
                p_req = urlparse(url)
                p_got = urlparse(browser_url)
                if p_req.scheme == p_got.scheme and p_req.netloc == p_got.netloc:
                    final_url = url
                    logger.debug(
                        "Same-host forward (%s -> %s) — using requested URL as page identity",
                        url,
                        browser_url,
                    )
                else:
                    final_url = browser_url
                    logger.debug("Redirect followed: %s -> %s", url, browser_url)
            else:
                final_url = url

            page_data = PageData(url=final_url, depth=depth)
            await self._trigger_layout(page)
            await self._click_tabs(page)
            page_data.inputs = await self._extract_inputs(page)
            page_data.links = await self._extract_links(page)
            # Use final_url so params added by the redirect (e.g. ?q=&tr=) are captured
            page_data.url_params = self._extract_url_params(final_url, page_data.links)

            return page_data

        except PlaywrightError as exc:
            logger.debug("Playwright error visiting %s: %s", url, exc)
            return None
        except Exception as exc:
            logger.debug("Unexpected error visiting %s: %s", url, exc)
            return None
        finally:
            if page and not page.is_closed():
                try:
                    await page.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Input extraction
    # ------------------------------------------------------------------

    async def _extract_inputs(self, page: Page) -> list[InputField]:
        """Return all testable ``<input>``, ``<textarea>``, and ``<select>`` elements.

        All DOM attribute reads are batched into a single ``page.evaluate()``
        call to eliminate per-element IPC round-trips. Elements that are
        disabled or read-only are filtered out in the browser process.
        """
        inputs: list[InputField] = []
        try:
            raw = await page.evaluate("""
                () => {
                    const skipTypes = new Set(
                        ['submit','button','reset','image','file','hidden']
                    );
                    const formFields = [];
                    const orphanFields = [];

                    // ── Form-bound inputs ──────────────────────────────────
                    document.querySelectorAll('form').forEach((form, formIdx) => {
                        const formId  = form.id || '';
                        const formSel = formId
                            ? '#' + formId
                            : 'form:nth-of-type(' + (formIdx + 1) + ')';
                        const action  = form.action || location.href;
                        const method  = (form.method || 'GET').toUpperCase();

                        form.querySelectorAll('input, textarea, select').forEach(el => {
                            const tag   = el.tagName.toLowerCase();
                            const itype = (el.getAttribute('type') || 'text').toLowerCase();
                            if (skipTypes.has(itype)) return;
                            if (el.disabled || el.readOnly)  return;

                            formFields.push({
                                tag, itype, formIdx,
                                name:    el.name    || null,
                                id:      el.id      || null,
                                formSel, action, method,
                            });
                        });
                    });

                    // ── Standalone inputs (not inside any form) ────────────
                    document.querySelectorAll(
                        'input:not(form input), ' +
                        'textarea:not(form textarea), ' +
                        'select:not(form select)'
                    ).forEach(el => {
                        const tag   = el.tagName.toLowerCase();
                        const itype = (el.getAttribute('type') || 'text').toLowerCase();
                        if (skipTypes.has(itype)) return;
                        if (el.disabled || el.readOnly) return;

                        orphanFields.push({
                            tag, itype,
                            name: el.name || null,
                            id:   el.id   || null,
                        });
                    });

                    return { formFields, orphanFields };
                }
            """)

            for f in raw["formFields"]:
                selector = self._build_selector(f["tag"], f["name"], f["id"], f["formIdx"])
                inputs.append(InputField(
                    selector=selector,
                    name=f["name"],
                    input_type=f["itype"] if f["tag"] == "input" else f["tag"],
                    form_selector=f["formSel"],
                    form_action=f["action"],
                    form_method=f["method"],
                ))

            for f in raw["orphanFields"]:
                selector = self._build_selector(f["tag"], f["name"], f["id"], 0)
                inputs.append(InputField(
                    selector=selector,
                    name=f["name"],
                    input_type=f["itype"] if f["tag"] == "input" else f["tag"],
                    form_selector=None,
                    form_action=None,
                    form_method="GET",
                ))

        except PlaywrightError as exc:
            logger.debug("Error extracting inputs from page: %s", exc)

        return inputs

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    async def _extract_links(self, page: Page) -> list[str]:
        """Return all in-scope, non-skippable absolute URLs from the page.

        Collects links from:

        - ``<a href>`` elements
        - ``<form action>`` attributes
        - Non-anchor elements with an ``href`` attribute (Dojo widgets often
          render menu items as ``<div>``/``<span>``/``<td>`` with ``href``)
        - ``onclick`` attributes containing ``location.href`` assignments
        - Dojo ``data-dojo-props="href: '...'"`` declarations
        - The Dojo widget registry (``window.dijit.registry``) for
          programmatically-created menus
        - JS dropdown menus revealed by clicking triggers (see
          :meth:`_expand_dropdowns`)
        """
        raw: list[str] = []
        try:
            # Anchor hrefs (browser resolves to absolute URLs via .href)
            hrefs: list[str] = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            raw.extend(hrefs)

            # Form actions
            actions: list[str] = await page.eval_on_selector_all(
                "form[action]", "els => els.map(e => e.action)"
            )
            raw.extend(actions)

            # href on non-anchor elements (Dojo/widget links on div/span/td/tr)
            non_anchor: list[str] = await page.eval_on_selector_all(
                "[href]:not(a)",
                "els => els.map(e => e.href || e.getAttribute('href')).filter(Boolean)",
            )
            raw.extend(non_anchor)

            # onclick attributes that directly assign location.href
            onclick_urls: list[str] = await page.evaluate(r"""
                () => {
                    const pat = /(?:location\.href|window\.location(?:\.href)?)\s*=\s*['"]([^'"]+)['"]/g;
                    const out = [];
                    document.querySelectorAll('[onclick]').forEach(el => {
                        const s = el.getAttribute('onclick') || '';
                        let m;
                        while ((m = pat.exec(s)) !== null) {
                            try { out.push(new URL(m[1], location.href).href); } catch (_) {}
                        }
                    });
                    return out;
                }
            """)
            raw.extend(onclick_urls)

            # Dojo data-dojo-props="href: '/path'" declarative links
            dojo_prop_urls: list[str] = await page.evaluate(r"""
                () => {
                    const out = [];
                    document.querySelectorAll('[data-dojo-props]').forEach(el => {
                        const props = el.getAttribute('data-dojo-props') || '';
                        const m = props.match(/\bhref\s*:\s*['"]([^'"]+)['"]/);
                        if (m) {
                            try { out.push(new URL(m[1], location.href).href); } catch (_) {}
                        }
                    });
                    return out;
                }
            """)
            raw.extend(dojo_prop_urls)

            # Dojo widget registry — catches programmatically-created menus
            dojo_registry_urls: list[str] = await page.evaluate("""
                () => {
                    const out = [];
                    if (!window.dijit || !window.dijit.registry) return out;
                    try {
                        window.dijit.registry.forEach(w => {
                            if (w.href) {
                                try { out.push(new URL(w.href, location.href).href); } catch (_) {}
                            }
                            if (w.getChildren) {
                                try {
                                    w.getChildren().forEach(c => {
                                        if (c.href) {
                                            try { out.push(new URL(c.href, location.href).href); } catch (_) {}
                                        }
                                    });
                                } catch (_) {}
                            }
                        });
                    } catch (_) {}
                    return out;
                }
            """)
            raw.extend(dojo_registry_urls)

        except PlaywrightError as exc:
            logger.debug("Error extracting static links: %s", exc)

        # Interactively open JS/Dojo dropdown menus and harvest hidden links
        raw.extend(await self._expand_dropdowns(page))

        links: list[str] = []
        seen: set[str] = set()
        for href in raw:
            norm = self._normalize_url(href)
            if norm and norm not in seen and self._in_scope(norm) and not self._should_skip(norm):
                seen.add(norm)
                links.append(norm)

        return links

    async def _expand_dropdowns(self, page: Page) -> list[str]:
        """Click JS/Dojo dropdown triggers and return links revealed in popups.

        Handles:

        - Dojo ``dijit/MenuBar`` items (``.dijitMenuBarItem``)
        - Dojo ``dijit/DropDownButton`` (``.dijitDropDownButton``)
        - Dojo ``data-dojo-type`` MenuBarItem / DropDownButton widgets
        - ARIA dropdown triggers (``[aria-haspopup=true]``)
        - Generic ``[data-toggle=dropdown]`` (Bootstrap-style hybrids)

        Each trigger is clicked once; Escape is sent to close the popup before
        moving to the next trigger. Per-trigger errors are swallowed so one
        broken widget does not abort the whole extraction.
        """
        raw: list[str] = []

        trigger_selectors = [
            ".dijitMenuBarItem",
            ".dijitDropDownButton",
            "[data-dojo-type*='MenuBarItem']",
            "[data-dojo-type*='DropDownButton']",
            "[aria-haspopup='true']",
            "[data-toggle='dropdown']",
        ]

        link_selectors = ", ".join([
            ".dijitPopup a[href]",
            ".dijitMenu a[href]",
            ".dijitMenuItem[href]",
            "[role='menu'] a[href]",
            "[role='menuitem'] a[href]",
            "[role='option'] a[href]",
        ])

        # JS snippet to scrape onclick-embedded URLs from open popup containers
        _onclick_in_popup = r"""
            () => {
                const pat = /(?:location\.href|window\.location(?:\.href)?)\s*=\s*['"]([^'"]+)['"]/g;
                const out = [];
                const scope = '.dijitPopup, .dijitMenu, [role="menu"], [role="listbox"]';
                document.querySelectorAll(scope).forEach(c =>
                    c.querySelectorAll('[onclick]').forEach(el => {
                        const s = el.getAttribute('onclick') || '';
                        let m;
                        while ((m = pat.exec(s)) !== null) {
                            try { out.push(new URL(m[1], location.href).href); } catch (_) {}
                        }
                    })
                );
                return out;
            }
        """

        tried: set[str] = set()  # dedup triggers by trimmed text content

        for selector in trigger_selectors:
            try:
                triggers = await page.query_selector_all(selector)
            except PlaywrightError as exc:
                logger.debug("Dropdown query for '%s' failed: %s", selector, exc)
                continue

            for trigger in triggers:
                try:
                    label = ((await trigger.text_content()) or "").strip()[:80]
                    if label in tried:
                        continue
                    tried.add(label)

                    await trigger.hover(timeout=2_000)
                    await trigger.click(timeout=2_000)

                    # Wait for a popup to become visible; fall back to fixed delay
                    try:
                        await page.wait_for_selector(
                            ".dijitPopup, [role='menu'], [role='listbox']",
                            state="visible",
                            timeout=1_000,
                        )
                    except PlaywrightError:
                        await page.wait_for_timeout(400)

                    # Harvest hrefs from revealed popup items
                    try:
                        popup_hrefs: list[str] = await page.eval_on_selector_all(
                            link_selectors,
                            "els => els.map(e => e.href || e.getAttribute('href')).filter(Boolean)",
                        )
                        raw.extend(popup_hrefs)
                    except PlaywrightError:
                        pass

                    # Harvest onclick-embedded URLs from popup items
                    try:
                        raw.extend(await page.evaluate(_onclick_in_popup))
                    except PlaywrightError:
                        pass

                    # Dismiss the popup before opening the next one
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(150)

                except PlaywrightError as exc:
                    logger.debug(
                        "Error interacting with dropdown trigger '%s': %s",
                        selector,
                        exc,
                    )

        return raw

    async def _trigger_layout(self, page: Page) -> None:
        """Fire a window resize event and call each Dojo widget's resize().

        Dojo layout widgets (BorderContainer, ContentPane, TabContainer, …)
        calculate their dimensions lazily on ``window.resize``.  Playwright
        opens a fixed viewport and never fires one, so nested panes — and the
        inputs inside them — remain invisible and undetectable until a resize
        occurs.
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

    async def _click_tabs(self, page: Page) -> None:
        """Click every tab trigger on the page to reveal hidden tab panels.

        Widget frameworks (Dojo TabContainer, jQuery UI Tabs, Bootstrap Tabs,
        ARIA tab lists, etc.) hide content in panels that are only rendered
        once their tab is activated.  Clicking each tab before extracting
        inputs ensures that all hidden fields are in the DOM and reachable.

        Uses a JS ``el.click()`` unconditionally — Playwright's own click()
        fails for elements that are outside the viewport or covered by Dojo's
        ``position:absolute`` layout layers.  Deduplication by visible text
        prevents the same logical tab from being clicked twice.
        """
        selectors = [
            "[role='tablist'] [role='tab']",
            "[role='tab']",
        ]
        clicked: set[str] = set()

        for sel in selectors:
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
                except PlaywrightError as exc:
                    logger.debug("Error clicking tab '%s': %s", label, exc)

    # ------------------------------------------------------------------
    # URL parameter extraction
    # ------------------------------------------------------------------

    def _extract_url_params(
        self, page_url: str, discovered_links: list[str]
    ) -> list[UrlParam]:
        """Return a ``UrlParam`` for every unique GET parameter found in *page_url*
        and all *discovered_links*.

        Scanning links as well as the page URL means GET parameters are
        discovered even when the target page is never crawled (e.g. because
        ``--max-pages`` or ``--max-depth`` limits were hit).

        Deduplicates by ``(netloc + path, param_name)`` so the same parameter
        on the same endpoint is only tested once regardless of how many
        distinct link values were observed.
        """
        params: list[UrlParam] = []
        seen: set[tuple[str, str]] = set()  # (netloc+path, param_name)

        for url in [page_url, *discovered_links]:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                continue
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if not qs:
                continue
            endpoint_key = parsed.netloc + parsed.path
            for name, values in qs.items():
                key = (endpoint_key, name)
                if key in seen:
                    continue
                seen.add(key)
                params.append(
                    UrlParam(
                        url=url,
                        param_name=name,
                        original_value=values[0] if values else "",
                    )
                )

        return params

    # ------------------------------------------------------------------
    # URL helpers
    # ------------------------------------------------------------------

    def _param_signature(self, url: str) -> tuple:
        """Return ``(netloc, path, frozenset(param_names))`` for *url*.

        Two URLs with the same path and the same set of GET parameter *names*
        but different *values* will produce an identical signature, allowing
        the crawler to skip re-crawling them.
        """
        try:
            parsed = urlparse(url)
            names = frozenset(parse_qs(parsed.query, keep_blank_values=True).keys())
            return (parsed.netloc, parsed.path, names)
        except Exception:
            return (url, "", frozenset())

    def _normalize_url(self, url: str) -> str:
        """Return a canonical, fragment-free version of *url*, or ``""`` on failure."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                return ""
            return urlunparse(parsed._replace(fragment=""))
        except Exception:
            return ""

    def _in_scope(self, url: str) -> bool:
        """Return *True* if *url* is within the allowed domain and scope path."""
        try:
            parsed = urlparse(url)
            if parsed.netloc != self.base_domain:
                return False
            if self.scope and not parsed.path.startswith(self.scope):
                return False
            return True
        except Exception:
            return False

    def _should_skip(self, url: str) -> bool:
        """Return *True* if the URL points to a non-HTML resource."""
        try:
            path = urlparse(url).path.lower()
            _, dot, ext = path.rpartition(".")
            return bool(dot) and f".{ext}" in _SKIP_EXTENSIONS
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Miscellaneous helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_selector(tag: str, name: Optional[str], el_id: Optional[str], idx: int) -> str:
        """Build the most specific CSS selector available for an element."""
        if el_id:
            return f"#{el_id}"
        if name:
            return f"{tag}[name='{name}']"
        return f"{tag}:nth-of-type({idx + 1})"

"""
Auth/Manager.py — Authentication management for XSS Tester.

Supports:
  - Form-based login described by a JSON auth-script file
  - Cookie injection via a raw cookie string
  - Storage-state persistence and automatic session re-authentication
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import BrowserContext, Error as PlaywrightError, Page

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Parsed representation of the --auth-script JSON file."""

    login_url: str
    username_selector: str
    password_selector: str
    username: str
    password: str
    submit_selector: str
    success_indicator: Optional[str] = None


class AuthManager:
    """Manages browser authentication state.

    Usage::

        manager = AuthManager(auth_script="auth.json", cookies_str=None)
        await manager.authenticate(context, base_url)
        # later, if a page redirects to the login URL:
        await manager.re_authenticate(context)
    """

    #: File used to persist Playwright storage state between the auth
    #: context and the main scanning context.
    STATE_FILE: str = ".auth_state.json"

    def __init__(
        self,
        auth_script: Optional[str],
        cookies_str: Optional[str],
    ) -> None:
        self.auth_config: Optional[AuthConfig] = None
        self.cookies_str: Optional[str] = cookies_str

        if auth_script:
            self._load_auth_config(auth_script)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def authenticate(self, context: BrowserContext, base_url: str) -> None:
        """Perform initial authentication against *context*.

        Tries cookie injection first; falls back to form-based login.
        """
        if self.cookies_str:
            await self._inject_cookies(context, base_url)
        elif self.auth_config:
            await self._do_login(context)

    async def re_authenticate(self, context: BrowserContext) -> None:
        """Re-run the login flow after session expiry detection."""
        logger.info("Session expired — re-authenticating…")
        if self.auth_config:
            await self._do_login(context)

    def is_login_page(self, url: str) -> bool:
        """Return *True* if *url* matches the configured login URL.

        Used to detect when the application has redirected an unauthenticated
        request back to the login page.
        """
        if not self.auth_config:
            return False
        login = self.auth_config.login_url.rstrip("/")
        # Strip query string for comparison
        current = url.split("?")[0].rstrip("/")
        return current == login or current.startswith(login)

    def has_auth(self) -> bool:
        """Return *True* if any authentication method is configured."""
        return bool(self.auth_config or self.cookies_str)

    def storage_state_exists(self) -> bool:
        """Return *True* if a persisted storage-state file exists."""
        return Path(self.STATE_FILE).exists()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_auth_config(self, path: str) -> None:
        """Parse the JSON auth-script at *path* into an :class:`AuthConfig`."""
        try:
            with open(path) as fh:
                data = json.load(fh)
        except FileNotFoundError:
            logger.error("Auth script not found: %s", path)
            return
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in auth script %s: %s", path, exc)
            return

        required = {
            "login_url",
            "username_selector",
            "password_selector",
            "username",
            "password",
            "submit_selector",
        }
        missing = required - data.keys()
        if missing:
            logger.error("Auth script missing required keys: %s", missing)
            return

        self.auth_config = AuthConfig(
            login_url=data["login_url"],
            username_selector=data["username_selector"],
            password_selector=data["password_selector"],
            username=data["username"],
            password=data["password"],
            submit_selector=data["submit_selector"],
            success_indicator=data.get("success_indicator"),
        )
        logger.debug("Auth config loaded from %s", path)

    async def _inject_cookies(self, context: BrowserContext, base_url: str) -> None:
        """Add cookies from the raw cookie string to *context*."""
        parsed = urlparse(base_url)
        domain = parsed.netloc
        secure = parsed.scheme == "https"

        cookies: list[dict] = []
        for part in self.cookies_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies.append(
                    {
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": domain,
                        "path": "/",
                        "secure": secure,
                    }
                )

        if cookies:
            await context.add_cookies(cookies)
            logger.info("Injected %d cookie(s) for domain %s", len(cookies), domain)
        else:
            logger.warning("No valid cookies found in --cookies string")

    async def _do_login(self, context: BrowserContext) -> None:
        """Perform form-based login and persist Playwright storage state.

        After a successful (or best-effort) login the storage state is written
        to :attr:`STATE_FILE` so the main scanning context can reuse it.
        """
        config = self.auth_config
        page: Optional[Page] = None

        try:
            page = await context.new_page()
            logger.info("Navigating to login page: %s", config.login_url)
            await page.goto(config.login_url, wait_until="networkidle", timeout=30_000)

            # Fill credentials
            await page.fill(config.username_selector, config.username)
            await page.fill(config.password_selector, config.password)
            await page.click(config.submit_selector)
            await page.wait_for_load_state("networkidle", timeout=15_000)

            # Optionally verify success
            if config.success_indicator:
                try:
                    await page.wait_for_selector(config.success_indicator, timeout=7_000)
                    logger.info("Login successful (success indicator found)")
                except PlaywrightError:
                    logger.warning(
                        "Login success indicator '%s' not found — proceeding anyway",
                        config.success_indicator,
                    )
            else:
                logger.info("Login submitted (no success indicator configured)")

            # Persist session so subsequent contexts can reuse it
            await context.storage_state(path=self.STATE_FILE)
            logger.debug("Storage state saved to %s", self.STATE_FILE)

        except PlaywrightError as exc:
            logger.error("Login failed with Playwright error: %s", exc)
        except Exception as exc:
            logger.error("Unexpected error during login: %s", exc)
        finally:
            if page and not page.is_closed():
                await page.close()

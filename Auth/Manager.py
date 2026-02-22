"""
Auth/Manager.py — Authentication management for XSS Tester.

Supports:
  - Form-based login described by a JSON auth-script file
  - Step-based login described by a JSON auth-script file with a "steps" array
  - Python script with async def authenticate(page) for maximum flexibility
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


@dataclass
class StepBasedAuthConfig:
    """Parsed representation of a step-based auth-script JSON file."""

    login_url: str
    steps: list[dict]
    success_selector: Optional[str] = None


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
        self.steps_config: Optional[StepBasedAuthConfig] = None
        self._script_path: Optional[str] = None
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
        elif self.steps_config:
            await self._do_login_steps(context)
        elif self._script_path:
            await self._do_login_python(context)

    async def re_authenticate(self, context: BrowserContext) -> None:
        """Re-run the login flow after session expiry detection."""
        logger.info("Session expired — re-authenticating…")
        if self.auth_config:
            await self._do_login(context)
        elif self.steps_config:
            await self._do_login_steps(context)
        elif self._script_path:
            await self._do_login_python(context)

    def is_login_page(self, url: str) -> bool:
        """Return *True* if *url* matches the configured login URL.

        Used to detect when the application has redirected an unauthenticated
        request back to the login page.
        """
        if self.auth_config:
            login_url = self.auth_config.login_url
        elif self.steps_config:
            login_url = self.steps_config.login_url
        else:
            return False  # Python scripts: no login_url; session expiry detection skipped
        login = login_url.rstrip("/")
        # Strip query string for comparison
        current = url.split("?")[0].rstrip("/")
        return current == login or current.startswith(login)

    def has_auth(self) -> bool:
        """Return *True* if any authentication method is configured."""
        return bool(self.auth_config or self.steps_config or self._script_path or self.cookies_str)

    def storage_state_exists(self) -> bool:
        """Return *True* if a persisted storage-state file exists."""
        return Path(self.STATE_FILE).exists()

    # ------------------------------------------------------------------
    # Private helpers — config loading
    # ------------------------------------------------------------------

    def _load_auth_config(self, path: str) -> None:
        """Dispatch auth-script loading based on file extension and content."""
        if path.endswith(".py"):
            self._load_python_script(path)
        else:
            self._load_json_auth(path)

    def _load_python_script(self, path: str) -> None:
        """Register a Python auth script for later dynamic execution."""
        if not Path(path).exists():
            logger.error("Auth script not found: %s", path)
            return
        self._script_path = path
        logger.debug("Python auth script registered: %s", path)

    def _load_json_auth(self, path: str) -> None:
        """Parse a JSON auth-script, dispatching to simple or step-based loader."""
        try:
            with open(path) as fh:
                data = json.load(fh)
        except FileNotFoundError:
            logger.error("Auth script not found: %s", path)
            return
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in auth script %s: %s", path, exc)
            return

        if "steps" in data:
            self._load_steps_config(data, path)
        else:
            self._load_simple_config(data, path)

    def _load_steps_config(self, data: dict, path: str) -> None:
        """Parse a step-based auth-script JSON into a :class:`StepBasedAuthConfig`."""
        if "login_url" not in data:
            logger.error("Steps auth script missing required 'login_url': %s", path)
            return
        if not isinstance(data.get("steps"), list) or not data["steps"]:
            logger.error("Steps auth script 'steps' must be a non-empty list: %s", path)
            return
        self.steps_config = StepBasedAuthConfig(
            login_url=data["login_url"],
            steps=data["steps"],
            success_selector=data.get("success_selector"),
        )
        logger.debug("Step-based auth loaded from %s (%d steps)", path, len(data["steps"]))

    def _load_simple_config(self, data: dict, path: str) -> None:
        """Parse a simple form-based auth-script JSON into an :class:`AuthConfig`."""
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

    # ------------------------------------------------------------------
    # Private helpers — login execution
    # ------------------------------------------------------------------

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

    async def _do_login_steps(self, context: BrowserContext) -> None:
        """Execute a step-based auth flow and persist Playwright storage state."""
        config = self.steps_config
        page: Optional[Page] = None

        try:
            page = await context.new_page()
            logger.info("Starting step-based login to: %s", config.login_url)

            for i, step in enumerate(config.steps):
                logger.debug("Executing step %d: %s", i + 1, step.get("action"))
                await self._execute_step(page, step)

            if config.success_selector:
                try:
                    await page.wait_for_selector(config.success_selector, timeout=7_000)
                    logger.info("Step-based login successful (success selector found)")
                except PlaywrightError:
                    logger.warning(
                        "Login success selector '%s' not found — proceeding anyway",
                        config.success_selector,
                    )
            else:
                logger.info("Step-based login completed (no success selector configured)")

            await context.storage_state(path=self.STATE_FILE)
            logger.debug("Storage state saved to %s", self.STATE_FILE)

        except PlaywrightError as exc:
            logger.error("Login failed with Playwright error: %s", exc)
        except Exception as exc:
            logger.error("Unexpected error during step-based login: %s", exc)
        finally:
            if page and not page.is_closed():
                await page.close()

    async def _execute_step(self, page: Page, step: dict) -> None:
        """Dispatch a single auth step to the appropriate Playwright call."""
        action = step.get("action")
        timeout = step.get("timeout")
        kwargs = {} if timeout is None else {"timeout": timeout}

        if action == "goto":
            await page.goto(step["url"], **kwargs)
        elif action == "fill":
            await page.fill(step["selector"], step["value"], **kwargs)
        elif action == "click":
            await page.click(step["selector"], **kwargs)
        elif action == "select_option":
            await page.select_option(step["selector"], step["value"], **kwargs)
        elif action == "check":
            await page.check(step["selector"], **kwargs)
        elif action == "uncheck":
            await page.uncheck(step["selector"], **kwargs)
        elif action == "press":
            await page.press(step["selector"], step["key"], **kwargs)
        elif action == "hover":
            await page.hover(step["selector"], **kwargs)
        elif action == "wait_for_selector":
            await page.wait_for_selector(step["selector"], **kwargs)
        elif action == "wait_for_load_state":
            state = step.get("state", "networkidle")
            await page.wait_for_load_state(state, **kwargs)
        elif action == "wait_for_timeout":
            await page.wait_for_timeout(step["ms"])
        else:
            logger.warning("Unknown auth step action '%s' — skipping", action)

    async def _do_login_python(self, context: BrowserContext) -> None:
        """Load and execute a Python auth script, then persist storage state."""
        import importlib.util

        page: Optional[Page] = None
        try:
            spec = importlib.util.spec_from_file_location("_xss_auth_script", self._script_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if not hasattr(module, "authenticate"):
                logger.error(
                    "Auth script '%s' must define async def authenticate(page)",
                    self._script_path,
                )
                return
            page = await context.new_page()
            await module.authenticate(page)
            await context.storage_state(path=self.STATE_FILE)
            logger.info("Python auth script completed — session state saved")
        except PlaywrightError as exc:
            logger.error("Login failed with Playwright error: %s", exc)
        except Exception as exc:
            logger.error("Unexpected error in auth script '%s': %s", self._script_path, exc)
        finally:
            if page and not page.is_closed():
                await page.close()

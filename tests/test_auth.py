"""
tests/test_auth.py — Unit tests for AuthManager pure/sync methods.

Async methods (authenticate, re_authenticate, _inject_cookies, _do_login)
require a live Playwright context and are not tested here.
"""
import json

import pytest

from Auth import AuthManager, StepBasedAuthConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_auth_config(tmp_path, **overrides) -> str:
    """Write a minimal valid auth-script JSON to *tmp_path* and return the path."""
    config = {
        "login_url": "https://example.com/login",
        "username_selector": "#username",
        "password_selector": "#password",
        "username": "admin",
        "password": "secret",
        "submit_selector": "button[type=submit]",
    }
    config.update(overrides)
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(config))
    return str(path)


# ---------------------------------------------------------------------------
# has_auth
# ---------------------------------------------------------------------------


class TestHasAuth:
    def test_returns_false_with_no_auth(self):
        m = AuthManager(auth_script=None, cookies_str=None)
        assert m.has_auth() is False

    def test_returns_true_with_cookies(self):
        m = AuthManager(auth_script=None, cookies_str="session=abc")
        assert m.has_auth() is True

    def test_returns_true_with_valid_auth_script(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.has_auth() is True

    def test_returns_false_with_invalid_auth_script_and_no_cookies(self):
        # A missing auth-script file means auth_config stays None
        m = AuthManager(auth_script="/nonexistent/auth.json", cookies_str=None)
        assert m.has_auth() is False

    def test_returns_true_when_both_provided(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str="token=xyz")
        assert m.has_auth() is True


# ---------------------------------------------------------------------------
# is_login_page
# ---------------------------------------------------------------------------


class TestIsLoginPage:
    def test_returns_false_with_no_auth_config(self):
        m = AuthManager(auth_script=None, cookies_str=None)
        assert m.is_login_page("https://example.com/login") is False

    def test_returns_true_for_exact_login_url(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.is_login_page("https://example.com/login") is True

    def test_returns_true_for_login_url_with_trailing_slash(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        # Both sides are rstrip("/") before comparison
        assert m.is_login_page("https://example.com/login/") is True

    def test_returns_true_for_login_url_with_query_string(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        # Query string is stripped before comparison
        assert m.is_login_page("https://example.com/login?next=/app") is True

    def test_returns_false_for_different_url(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.is_login_page("https://example.com/dashboard") is False

    def test_returns_true_for_subpath_of_login_url(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        # startswith check means /login/oauth also matches
        assert m.is_login_page("https://example.com/login/oauth") is True

    def test_returns_false_for_different_domain(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.is_login_page("https://attacker.com/login") is False


# ---------------------------------------------------------------------------
# _load_auth_config
# ---------------------------------------------------------------------------


class TestLoadAuthConfig:
    def test_loads_valid_config(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.auth_config is not None
        assert m.auth_config.login_url == "https://example.com/login"
        assert m.auth_config.username == "admin"
        assert m.auth_config.password == "secret"
        assert m.auth_config.username_selector == "#username"
        assert m.auth_config.password_selector == "#password"
        assert m.auth_config.submit_selector == "button[type=submit]"

    def test_default_success_indicator_is_none(self, tmp_path):
        path = _write_auth_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.auth_config.success_indicator is None

    def test_optional_success_indicator_loaded(self, tmp_path):
        path = _write_auth_config(tmp_path, success_indicator="#welcome-banner")
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.auth_config.success_indicator == "#welcome-banner"

    def test_missing_file_leaves_auth_config_none(self):
        m = AuthManager(auth_script="/nonexistent/path/auth.json", cookies_str=None)
        assert m.auth_config is None

    def test_invalid_json_leaves_auth_config_none(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        m = AuthManager(auth_script=str(bad), cookies_str=None)
        assert m.auth_config is None

    def test_missing_required_key_leaves_auth_config_none(self, tmp_path):
        # Omit 'password' — should log an error and leave auth_config as None
        config = {
            "login_url": "https://example.com/login",
            "username_selector": "#user",
            "password_selector": "#pass",
            "username": "admin",
            # "password" intentionally missing
            "submit_selector": "button",
        }
        bad = tmp_path / "missing_key.json"
        bad.write_text(json.dumps(config))
        m = AuthManager(auth_script=str(bad), cookies_str=None)
        assert m.auth_config is None

    def test_all_required_keys_must_be_present(self, tmp_path):
        required = [
            "login_url",
            "username_selector",
            "password_selector",
            "username",
            "password",
            "submit_selector",
        ]
        full_config = {
            "login_url": "https://example.com/login",
            "username_selector": "#u",
            "password_selector": "#p",
            "username": "admin",
            "password": "secret",
            "submit_selector": "button",
        }
        # Remove each required key one at a time and verify config stays None
        for key in required:
            partial = {k: v for k, v in full_config.items() if k != key}
            path = tmp_path / f"missing_{key}.json"
            path.write_text(json.dumps(partial))
            m = AuthManager(auth_script=str(path), cookies_str=None)
            assert m.auth_config is None, f"Expected auth_config=None when '{key}' is missing"


# ---------------------------------------------------------------------------
# Helpers for step-based / Python script tests
# ---------------------------------------------------------------------------


def _write_steps_config(tmp_path, **overrides) -> str:
    """Write a minimal valid step-based auth-script JSON and return the path."""
    config = {
        "login_url": "https://example.com/login",
        "steps": [
            {"action": "goto", "url": "https://example.com/login"},
            {"action": "fill", "selector": "#user", "value": "admin"},
            {"action": "click", "selector": "[type=submit]"},
        ],
    }
    config.update(overrides)
    path = tmp_path / "steps_auth.json"
    path.write_text(json.dumps(config))
    return str(path)


def _write_py_script(tmp_path, content: str = None) -> str:
    """Write a minimal Python auth script and return the path."""
    if content is None:
        content = "async def authenticate(page):\n    pass\n"
    path = tmp_path / "auth_flow.py"
    path.write_text(content)
    return str(path)


# ---------------------------------------------------------------------------
# TestStepsAuthConfig
# ---------------------------------------------------------------------------


class TestStepsAuthConfig:
    def test_valid_steps_json_sets_steps_config(self, tmp_path):
        path = _write_steps_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.steps_config is not None
        assert m.auth_config is None

    def test_has_auth_returns_true_with_steps_config(self, tmp_path):
        path = _write_steps_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.has_auth() is True

    def test_is_login_page_uses_steps_config_login_url(self, tmp_path):
        path = _write_steps_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.is_login_page("https://example.com/login") is True
        assert m.is_login_page("https://example.com/dashboard") is False

    def test_missing_login_url_leaves_steps_config_none(self, tmp_path):
        config = {
            "steps": [{"action": "goto", "url": "https://example.com/login"}],
        }
        path = tmp_path / "no_url.json"
        path.write_text(json.dumps(config))
        m = AuthManager(auth_script=str(path), cookies_str=None)
        assert m.steps_config is None

    def test_empty_steps_list_leaves_steps_config_none(self, tmp_path):
        path = _write_steps_config(tmp_path, steps=[])
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.steps_config is None

    def test_success_selector_is_loaded_when_present(self, tmp_path):
        path = _write_steps_config(tmp_path, success_selector=".dashboard")
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.steps_config is not None
        assert m.steps_config.success_selector == ".dashboard"

    def test_success_selector_defaults_to_none_when_absent(self, tmp_path):
        path = _write_steps_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.steps_config is not None
        assert m.steps_config.success_selector is None

    def test_steps_list_is_preserved(self, tmp_path):
        path = _write_steps_config(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert len(m.steps_config.steps) == 3
        assert m.steps_config.steps[0]["action"] == "goto"


# ---------------------------------------------------------------------------
# TestPythonScriptAuth
# ---------------------------------------------------------------------------


class TestPythonScriptAuth:
    def test_valid_py_file_sets_script_path(self, tmp_path):
        path = _write_py_script(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m._script_path == path
        assert m.auth_config is None
        assert m.steps_config is None

    def test_has_auth_returns_true_when_script_path_set(self, tmp_path):
        path = _write_py_script(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        assert m.has_auth() is True

    def test_missing_py_file_leaves_script_path_none(self, tmp_path):
        missing = str(tmp_path / "nonexistent.py")
        m = AuthManager(auth_script=missing, cookies_str=None)
        assert m._script_path is None

    def test_is_login_page_returns_false_for_python_script_mode(self, tmp_path):
        path = _write_py_script(tmp_path)
        m = AuthManager(auth_script=path, cookies_str=None)
        # Python scripts have no login_url — session expiry detection is skipped
        assert m.is_login_page("https://example.com/login") is False
        assert m.is_login_page("https://example.com/dashboard") is False

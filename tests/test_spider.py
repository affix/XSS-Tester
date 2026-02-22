"""
tests/test_spider.py — Unit tests for Spider pure/sync methods.

All tests operate on Spider without a live Playwright context; the async
crawl methods are not tested here.
"""
import asyncio
from unittest.mock import MagicMock

import pytest

from Auth import AuthManager
from Spider import Spider


def make_spider(base_url: str = "https://example.com", scope: str | None = None) -> Spider:
    """Return a Spider instance suitable for testing pure methods."""
    return Spider(
        context=MagicMock(),
        base_url=base_url,
        scope=scope,
        max_pages=100,
        max_depth=3,
        delay=0.0,
        semaphore=asyncio.Semaphore(3),
        auth_manager=AuthManager(auth_script=None, cookies_str=None),
        reporter=MagicMock(),
        shutdown_event=asyncio.Event(),
    )


# ---------------------------------------------------------------------------
# _normalize_url
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_strips_fragment(self):
        s = make_spider()
        assert s._normalize_url("https://example.com/page#section") == "https://example.com/page"

    def test_preserves_query_string(self):
        s = make_spider()
        assert s._normalize_url("https://example.com/page?q=1") == "https://example.com/page?q=1"

    def test_rejects_javascript_scheme(self):
        s = make_spider()
        assert s._normalize_url("javascript:alert(1)") == ""

    def test_rejects_ftp_scheme(self):
        s = make_spider()
        assert s._normalize_url("ftp://example.com/file") == ""

    def test_rejects_data_uri(self):
        s = make_spider()
        assert s._normalize_url("data:text/html,<h1>") == ""

    def test_rejects_empty_string(self):
        s = make_spider()
        assert s._normalize_url("") == ""

    def test_accepts_http(self):
        s = make_spider()
        assert s._normalize_url("http://example.com/page") == "http://example.com/page"

    def test_accepts_https(self):
        s = make_spider()
        assert s._normalize_url("https://example.com/page") == "https://example.com/page"

    def test_fragment_only_stripped_not_path(self):
        s = make_spider()
        result = s._normalize_url("https://example.com/a/b?x=1#top")
        assert result == "https://example.com/a/b?x=1"


# ---------------------------------------------------------------------------
# _in_scope
# ---------------------------------------------------------------------------


class TestInScope:
    def test_same_domain_no_scope_in_scope(self):
        s = make_spider("https://example.com")
        assert s._in_scope("https://example.com/page") is True

    def test_different_domain_out_of_scope(self):
        s = make_spider("https://example.com")
        assert s._in_scope("https://attacker.com/page") is False

    def test_subdomain_out_of_scope(self):
        s = make_spider("https://example.com")
        assert s._in_scope("https://sub.example.com/page") is False

    def test_scope_path_match(self):
        s = make_spider("https://example.com", scope="/app/")
        assert s._in_scope("https://example.com/app/dashboard") is True

    def test_scope_path_no_match(self):
        s = make_spider("https://example.com", scope="/app/")
        assert s._in_scope("https://example.com/admin/panel") is False

    def test_scope_path_exact_boundary(self):
        s = make_spider("https://example.com", scope="/app/")
        assert s._in_scope("https://example.com/application/page") is False

    def test_no_scope_allows_any_path(self):
        s = make_spider("https://example.com")
        assert s._in_scope("https://example.com/anything/goes") is True


# ---------------------------------------------------------------------------
# _should_skip
# ---------------------------------------------------------------------------


class TestShouldSkip:
    @pytest.mark.parametrize("ext", [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".css", ".js", ".mjs",
        ".pdf", ".zip", ".tar", ".gz",
        ".mp4", ".mp3", ".wav",
        ".woff", ".woff2", ".ttf",
        ".xml", ".csv",
    ])
    def test_skips_binary_and_static(self, ext):
        s = make_spider()
        assert s._should_skip(f"https://example.com/file{ext}") is True

    def test_does_not_skip_html(self):
        s = make_spider()
        assert s._should_skip("https://example.com/page.html") is False

    def test_does_not_skip_php(self):
        s = make_spider()
        assert s._should_skip("https://example.com/page.php") is False

    def test_does_not_skip_no_extension(self):
        s = make_spider()
        assert s._should_skip("https://example.com/search") is False

    def test_does_not_skip_asp(self):
        s = make_spider()
        assert s._should_skip("https://example.com/page.asp") is False


# ---------------------------------------------------------------------------
# _build_selector
# ---------------------------------------------------------------------------


class TestBuildSelector:
    def test_prefers_id_over_name(self):
        assert Spider._build_selector("input", "username", "user-field", 0) == "#user-field"

    def test_falls_back_to_name_when_no_id(self):
        assert Spider._build_selector("input", "username", None, 0) == "input[name='username']"

    def test_falls_back_to_nth_when_no_id_or_name(self):
        assert Spider._build_selector("input", None, None, 2) == "input:nth-of-type(3)"

    def test_nth_of_type_is_one_based(self):
        assert Spider._build_selector("textarea", None, None, 0) == "textarea:nth-of-type(1)"

    def test_textarea_with_name(self):
        assert Spider._build_selector("textarea", "body", None, 0) == "textarea[name='body']"

    def test_select_with_id(self):
        assert Spider._build_selector("select", "country", "country-select", 1) == "#country-select"


# ---------------------------------------------------------------------------
# _extract_url_params
# ---------------------------------------------------------------------------


class TestExtractUrlParams:
    def test_extracts_params_from_page_url(self):
        s = make_spider()
        params = s._extract_url_params("https://example.com/search?q=hello&page=2", [])
        names = {p.param_name for p in params}
        assert names == {"q", "page"}

    def test_extracts_params_from_discovered_links(self):
        s = make_spider()
        params = s._extract_url_params(
            "https://example.com/home",
            ["https://example.com/profile?user=admin"],
        )
        names = {p.param_name for p in params}
        assert "user" in names

    def test_deduplicates_same_endpoint_and_param(self):
        s = make_spider()
        params = s._extract_url_params(
            "https://example.com/search?q=hello",
            ["https://example.com/search?q=world"],  # same endpoint + param, different value
        )
        q_params = [p for p in params if p.param_name == "q"]
        assert len(q_params) == 1

    def test_same_param_different_endpoints_both_kept(self):
        s = make_spider()
        params = s._extract_url_params(
            "https://example.com/search?q=hello",
            ["https://example.com/filter?q=world"],  # different endpoint
        )
        q_params = [p for p in params if p.param_name == "q"]
        assert len(q_params) == 2

    def test_no_params_returns_empty(self):
        s = make_spider()
        assert s._extract_url_params("https://example.com/page", []) == []

    def test_preserves_original_value(self):
        s = make_spider()
        params = s._extract_url_params("https://example.com/?id=123", [])
        assert params[0].original_value == "123"

    def test_captures_redirect_params(self):
        # Simulates level19.php redirecting to level19.php?q=foo&tr=encoded
        s = make_spider()
        params = s._extract_url_params(
            "https://example.com/level19.php?q=muhaha&tr=encoded==",
            [],
        )
        names = {p.param_name for p in params}
        assert names == {"q", "tr"}

    def test_ignores_non_http_links(self):
        s = make_spider()
        params = s._extract_url_params(
            "https://example.com/page",
            ["javascript:void(0)", "mailto:user@example.com"],
        )
        assert params == []

    def test_url_stored_on_param(self):
        s = make_spider()
        params = s._extract_url_params("https://example.com/?x=1", [])
        assert params[0].url == "https://example.com/?x=1"

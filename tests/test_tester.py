"""
tests/test_tester.py — Unit tests for XSSTester pure/sync methods.

All tests operate without a live Playwright context; only methods that
perform pure string/file manipulation are exercised here.
"""
import asyncio
from unittest.mock import MagicMock

import pytest

from Auth import AuthManager
from Models import UrlParam
from Tester import XSSTester


def make_tester(payloads_file: str = "nonexistent.txt") -> XSSTester:
    """Return an XSSTester suitable for testing pure sync methods."""
    return XSSTester(
        context=MagicMock(),
        payloads_file=payloads_file,
        reporter=MagicMock(),
        delay=0.0,
        semaphore=asyncio.Semaphore(3),
        auth_manager=AuthManager(auth_script=None, cookies_str=None),
        interactsh_url=None,
        shutdown_event=asyncio.Event(),
    )


# ---------------------------------------------------------------------------
# _load_payloads
# ---------------------------------------------------------------------------


class TestLoadPayloads:
    def test_loads_payloads_from_file(self, tmp_path):
        pf = tmp_path / "payloads.txt"
        pf.write_text("<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n")
        t = make_tester(str(pf))
        t._load_payloads()
        assert len(t._payloads) == 2

    def test_skips_comment_lines(self, tmp_path):
        pf = tmp_path / "payloads.txt"
        pf.write_text("# this is a comment\n<script>alert(1)</script>\n")
        t = make_tester(str(pf))
        t._load_payloads()
        assert t._payloads == ["<script>alert(1)</script>"]

    def test_skips_blank_lines(self, tmp_path):
        pf = tmp_path / "payloads.txt"
        pf.write_text("\n<script>alert(1)</script>\n\n")
        t = make_tester(str(pf))
        t._load_payloads()
        assert t._payloads == ["<script>alert(1)</script>"]

    def test_missing_file_yields_empty(self, tmp_path):
        t = make_tester(str(tmp_path / "no_such_file.txt"))
        t._load_payloads()
        assert t._payloads == []

    def test_strips_whitespace_from_lines(self, tmp_path):
        pf = tmp_path / "payloads.txt"
        pf.write_text("  <script>alert(1)</script>  \n")
        t = make_tester(str(pf))
        t._load_payloads()
        assert t._payloads == ["<script>alert(1)</script>"]

    def test_inline_comment_not_treated_as_comment(self, tmp_path):
        # Only lines that *start* with # are comments
        pf = tmp_path / "payloads.txt"
        pf.write_text('<img src=x onerror="alert(1)"># not a comment\n')
        t = make_tester(str(pf))
        t._load_payloads()
        assert len(t._payloads) == 1

    def test_multiple_payloads_order_preserved(self, tmp_path):
        pf = tmp_path / "payloads.txt"
        pf.write_text("A\nB\nC\n")
        t = make_tester(str(pf))
        t._load_payloads()
        assert t._payloads == ["A", "B", "C"]


# ---------------------------------------------------------------------------
# _build_injected_url
# ---------------------------------------------------------------------------


class TestBuildInjectedUrl:
    def test_replaces_target_param(self):
        t = make_tester()
        param = UrlParam(
            url="https://example.com/?q=hello",
            param_name="q",
            original_value="hello",
        )
        result = t._build_injected_url(param, "PAYLOAD")
        assert "q=PAYLOAD" in result
        assert result.startswith("https://example.com/")

    def test_preserves_other_params(self):
        t = make_tester()
        param = UrlParam(
            url="https://example.com/?q=hello&page=2",
            param_name="q",
            original_value="hello",
        )
        result = t._build_injected_url(param, "PAYLOAD")
        assert "page=2" in result

    def test_replaces_only_named_param(self):
        t = make_tester()
        param = UrlParam(
            url="https://example.com/?a=1&b=2",
            param_name="a",
            original_value="1",
        )
        result = t._build_injected_url(param, "PAYLOAD")
        assert "a=PAYLOAD" in result
        assert "b=2" in result

    def test_result_has_same_scheme_and_host(self):
        from urllib.parse import urlparse

        t = make_tester()
        param = UrlParam(
            url="https://example.com/?id=123",
            param_name="id",
            original_value="123",
        )
        result = t._build_injected_url(param, "XSS")
        parsed = urlparse(result)
        assert parsed.scheme == "https"
        assert parsed.netloc == "example.com"

    def test_result_has_same_path(self):
        from urllib.parse import urlparse

        t = make_tester()
        param = UrlParam(
            url="https://example.com/search?q=test",
            param_name="q",
            original_value="test",
        )
        result = t._build_injected_url(param, "XSS")
        assert urlparse(result).path == "/search"


# ---------------------------------------------------------------------------
# _resolve_oob_payload
# ---------------------------------------------------------------------------


class TestResolveOobPayload:
    def test_no_placeholder_returns_unchanged(self):
        t = make_tester()
        payload = "<script>alert(1)</script>"
        assert t._resolve_oob_payload(payload, "abc123") == payload

    def test_placeholder_without_interactsh_replaced_with_empty(self):
        t = make_tester()
        # _interactsh is None by default
        payload = '<script src="http://INTERACTSH_HOST/x"></script>'
        result = t._resolve_oob_payload(payload, "abc123")
        assert "INTERACTSH_HOST" not in result
        assert result == '<script src="http:///x"></script>'

    def test_placeholder_with_interactsh_replaced_with_host(self):
        t = make_tester()
        mock_interactsh = MagicMock()
        mock_interactsh.interaction_host.return_value = "corr0000000000000000nonce.oast.live"
        t._interactsh = mock_interactsh
        payload = '<script src="http://INTERACTSH_HOST/x"></script>'
        result = t._resolve_oob_payload(payload, "nonce")
        assert "INTERACTSH_HOST" not in result
        assert "corr0000000000000000nonce.oast.live" in result

    def test_interactsh_interaction_host_called_with_test_id(self):
        t = make_tester()
        mock_interactsh = MagicMock()
        mock_interactsh.interaction_host.return_value = "host.oast.live"
        t._interactsh = mock_interactsh
        t._resolve_oob_payload("INTERACTSH_HOST", "mytestid")
        mock_interactsh.interaction_host.assert_called_once_with("mytestid")

    def test_all_occurrences_of_placeholder_replaced(self):
        t = make_tester()
        # _interactsh None — both placeholders should become ""
        payload = "http://INTERACTSH_HOST/ and also INTERACTSH_HOST"
        result = t._resolve_oob_payload(payload, "id")
        assert "INTERACTSH_HOST" not in result

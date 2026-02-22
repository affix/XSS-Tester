"""
tests/test_models.py — Unit tests for Models dataclasses.

These are lightweight construction and default-value tests that do not
require any external dependencies.
"""
from Models import Finding, InputField, PageData, UrlParam


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def _make(self, **kwargs) -> Finding:
        defaults = dict(
            url="https://example.com",
            parameter="q",
            payload="<script>alert(1)</script>",
            detection_method="alert-dialog",
            test_id="abc1234567890",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_required_fields_stored(self):
        f = self._make()
        assert f.url == "https://example.com"
        assert f.parameter == "q"
        assert f.payload == "<script>alert(1)</script>"
        assert f.detection_method == "alert-dialog"
        assert f.test_id == "abc1234567890"

    def test_default_severity_is_high(self):
        f = self._make()
        assert f.severity == "High"

    def test_timestamp_is_populated(self):
        f = self._make()
        assert f.timestamp  # non-empty string
        assert "T" in f.timestamp  # ISO-8601 includes 'T' separator

    def test_timestamp_is_utc(self):
        f = self._make()
        # UTC ISO strings end with '+00:00' or 'Z'
        assert f.timestamp.endswith("+00:00") or f.timestamp.endswith("Z")

    def test_custom_severity_accepted(self):
        f = self._make(severity="Critical")
        assert f.severity == "Critical"

    def test_two_findings_have_different_timestamps_are_possible(self):
        # Both can share the same timestamp if created in the same microsecond,
        # but each must have a non-empty timestamp
        f1 = self._make(test_id="aaa")
        f2 = self._make(test_id="bbb")
        assert f1.timestamp
        assert f2.timestamp

    def test_all_detection_method_values_stored(self):
        for method in ("alert-dialog", "dom-mutation", "interactsh-oob"):
            f = self._make(detection_method=method)
            assert f.detection_method == method


# ---------------------------------------------------------------------------
# PageData
# ---------------------------------------------------------------------------


class TestPageData:
    def test_url_and_depth_stored(self):
        p = PageData(url="https://example.com/page", depth=2)
        assert p.url == "https://example.com/page"
        assert p.depth == 2

    def test_default_inputs_is_empty_list(self):
        p = PageData(url="https://example.com", depth=0)
        assert p.inputs == []

    def test_default_url_params_is_empty_list(self):
        p = PageData(url="https://example.com", depth=0)
        assert p.url_params == []

    def test_default_links_is_empty_list(self):
        p = PageData(url="https://example.com", depth=0)
        assert p.links == []

    def test_default_lists_are_independent(self):
        # Each instance should get its own list, not share a mutable default
        p1 = PageData(url="https://example.com", depth=0)
        p2 = PageData(url="https://example.com", depth=0)
        p1.links.append("https://example.com/a")
        assert p2.links == []


# ---------------------------------------------------------------------------
# InputField
# ---------------------------------------------------------------------------


class TestInputField:
    def test_construction_with_all_fields(self):
        inp = InputField(
            selector="#username",
            name="username",
            input_type="text",
            form_selector="form#login",
            form_action="https://example.com/login",
            form_method="POST",
        )
        assert inp.selector == "#username"
        assert inp.name == "username"
        assert inp.input_type == "text"
        assert inp.form_selector == "form#login"
        assert inp.form_action == "https://example.com/login"
        assert inp.form_method == "POST"

    def test_optional_fields_accept_none(self):
        inp = InputField(
            selector="input:nth-of-type(1)",
            name=None,
            input_type="text",
            form_selector=None,
            form_action=None,
            form_method="GET",
        )
        assert inp.name is None
        assert inp.form_selector is None
        assert inp.form_action is None

    def test_textarea_type(self):
        inp = InputField(
            selector="textarea[name='body']",
            name="body",
            input_type="textarea",
            form_selector="form",
            form_action=None,
            form_method="POST",
        )
        assert inp.input_type == "textarea"

    def test_select_type(self):
        inp = InputField(
            selector="#country-select",
            name="country",
            input_type="select",
            form_selector="form",
            form_action=None,
            form_method="GET",
        )
        assert inp.input_type == "select"


# ---------------------------------------------------------------------------
# UrlParam
# ---------------------------------------------------------------------------


class TestUrlParam:
    def test_construction(self):
        p = UrlParam(
            url="https://example.com/search?q=hello",
            param_name="q",
            original_value="hello",
        )
        assert p.url == "https://example.com/search?q=hello"
        assert p.param_name == "q"
        assert p.original_value == "hello"

    def test_empty_original_value(self):
        p = UrlParam(
            url="https://example.com/?id=",
            param_name="id",
            original_value="",
        )
        assert p.original_value == ""

    def test_param_name_with_special_chars(self):
        p = UrlParam(
            url="https://example.com/?redirect_to=/app",
            param_name="redirect_to",
            original_value="/app",
        )
        assert p.param_name == "redirect_to"

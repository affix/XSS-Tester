"""
tests/test_reporter.py — Unit tests for Reporter.

Only pure data-manipulation behaviour is tested (counters, findings list,
JSON serialisation). Rich console output is not asserted on.
"""
import json

import pytest

from Models import Finding
from Reporter import Reporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_reporter(tmp_path) -> Reporter:
    return Reporter(output_file=str(tmp_path / "findings.json"))


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        url="https://example.com",
        parameter="q",
        payload="<script>alert(1)</script>",
        detection_method="alert-dialog",
        test_id="abc1234567890",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------


class TestInitialState:
    def test_findings_starts_empty(self, tmp_path):
        r = make_reporter(tmp_path)
        assert r.findings == []

    def test_pages_crawled_starts_at_zero(self, tmp_path):
        r = make_reporter(tmp_path)
        assert r.pages_crawled == 0

    def test_inputs_tested_starts_at_zero(self, tmp_path):
        r = make_reporter(tmp_path)
        assert r.inputs_tested == 0

    def test_output_file_stored(self, tmp_path):
        out = str(tmp_path / "out.json")
        r = Reporter(output_file=out)
        assert r.output_file == out


# ---------------------------------------------------------------------------
# log_finding
# ---------------------------------------------------------------------------


class TestLogFinding:
    def test_log_finding_appends_to_list(self, tmp_path):
        r = make_reporter(tmp_path)
        f = make_finding()
        r.log_finding(f)
        assert len(r.findings) == 1
        assert r.findings[0] is f

    def test_log_finding_appends_multiple(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding(test_id="aaa"))
        r.log_finding(make_finding(test_id="bbb"))
        assert len(r.findings) == 2

    def test_log_finding_preserves_order(self, tmp_path):
        r = make_reporter(tmp_path)
        ids = ["first", "second", "third"]
        for i in ids:
            r.log_finding(make_finding(test_id=i))
        assert [f.test_id for f in r.findings] == ids


# ---------------------------------------------------------------------------
# save
# ---------------------------------------------------------------------------


class TestSave:
    def test_save_creates_file(self, tmp_path):
        r = make_reporter(tmp_path)
        r.save()
        assert (tmp_path / "findings.json").exists()

    def test_save_with_no_findings_writes_empty_list(self, tmp_path):
        r = make_reporter(tmp_path)
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data == []

    def test_save_writes_valid_json(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding())
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert isinstance(data, list)
        assert len(data) == 1

    def test_save_preserves_url(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding(url="https://target.com/vuln"))
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["url"] == "https://target.com/vuln"

    def test_save_preserves_parameter(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding(parameter="?id"))
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["parameter"] == "?id"

    def test_save_preserves_severity(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding())
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["severity"] == "High"

    def test_save_preserves_test_id(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding(test_id="uniqueid12345"))
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert data[0]["test_id"] == "uniqueid12345"

    def test_save_multiple_findings(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding(test_id="aaa"))
        r.log_finding(make_finding(test_id="bbb"))
        r.save()
        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data) == 2
        assert {d["test_id"] for d in data} == {"aaa", "bbb"}

    def test_save_is_idempotent(self, tmp_path):
        r = make_reporter(tmp_path)
        r.log_finding(make_finding())
        r.save()
        r.save()  # second save should not duplicate
        data = json.loads((tmp_path / "findings.json").read_text())
        assert len(data) == 1

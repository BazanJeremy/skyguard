"""
SkyGuard — findings gate tests
==============================
The CI gate used to compare a hard-coded list of five findings with a
threshold equal to that list's own critical count: it could not fail.

The findings are now derived from the JUnit report of the security tests.
A documented weakness is a finding only if its ``TestW<n>...`` class ran and
every one of its tests passed; the gate fails when what the tests show
differs from the documented baseline.
"""

from __future__ import annotations

import json

import pytest

from src.gate.findings import (
    BASELINE,
    EXIT_DEVIATION,
    EXIT_OK,
    EXIT_UNUSABLE,
    evaluate,
    main,
)

pytestmark = pytest.mark.security

_CLASS_OF = {
    "W1": "TestW1NoRateLimiting",
    "W2": "TestW2HardcodedSecret",
    "W3": "TestW3IDOR",
    "W4": "TestW4DebugEndpoint",
    "W5": "TestW5InformationDisclosure",
}


def _junit(cases: list[tuple[str, str, bool]]) -> str:
    """Build a JUnit report from (class name, test name, passed) triples."""
    body = ""
    for class_name, name, passed in cases:
        classname = f"tests.security.test_efb_api.{class_name}"
        failure = "" if passed else '<failure message="boom">boom</failure>'
        body += f'<testcase classname="{classname}" name="{name}">{failure}</testcase>'
    return f'<testsuites><testsuite name="pytest">{body}</testsuite></testsuites>'


def _all_demonstrated() -> list[tuple[str, str, bool]]:
    return [(cls, "test_a", True) for cls in _CLASS_OF.values()]


def _write(tmp_path, cases):
    report = tmp_path / "junit.xml"
    report.write_text(_junit(cases), encoding="utf-8")
    return report


class TestEvaluate:
    def test_baseline_fully_demonstrated_is_clean(self, tmp_path):
        result = evaluate(_write(tmp_path, _all_demonstrated()))
        assert result.deviations == []
        assert [f["id"] for f in result.findings] == sorted(BASELINE)

    def test_findings_carry_baseline_metadata_and_test_evidence(self, tmp_path):
        result = evaluate(_write(tmp_path, _all_demonstrated()))
        w2 = next(f for f in result.findings if f["id"] == "W2")
        assert w2["severity"] == "critical"
        assert w2["title"] == BASELINE["W2"]["title"]
        assert w2["evidence"] == "TestW2HardcodedSecret: 1/1 tests passed"

    def test_weakness_without_any_test_is_a_deviation(self, tmp_path):
        cases = [c for c in _all_demonstrated() if c[0] != _CLASS_OF["W4"]]
        result = evaluate(_write(tmp_path, cases))
        assert [f["id"] for f in result.findings] == ["W1", "W2", "W3", "W5"]
        assert any("W4" in d and "no test" in d for d in result.deviations)

    def test_weakness_whose_test_fails_is_not_a_finding(self, tmp_path):
        cases = _all_demonstrated() + [(_CLASS_OF["W2"], "test_b", False)]
        result = evaluate(_write(tmp_path, cases))
        assert "W2" not in [f["id"] for f in result.findings]
        assert any("W2" in d and "1 of 2" in d for d in result.deviations)

    def test_undocumented_weakness_class_is_a_deviation(self, tmp_path):
        cases = _all_demonstrated() + [("TestW6NewHole", "test_a", True)]
        result = evaluate(_write(tmp_path, cases))
        assert any("W6" in d and "not in the baseline" in d for d in result.deviations)

    def test_other_test_classes_are_ignored(self, tmp_path):
        cases = _all_demonstrated() + [("TestAuthentication", "test_login", False)]
        assert evaluate(_write(tmp_path, cases)).deviations == []


class TestCommandLine:
    def test_clean_run_exits_0_and_writes_the_findings(self, tmp_path, capsys):
        report = _write(tmp_path, _all_demonstrated())
        out = tmp_path / "findings.json"
        assert main(["--junit", str(report), "--out", str(out)]) == EXIT_OK
        written = json.loads(out.read_text(encoding="utf-8"))
        assert [f["id"] for f in written] == sorted(BASELINE)

    def test_deviation_exits_1_and_still_writes_the_findings(self, tmp_path, capsys):
        cases = _all_demonstrated() + [("TestW6NewHole", "test_a", True)]
        report = _write(tmp_path, cases)
        out = tmp_path / "findings.json"
        assert main(["--junit", str(report), "--out", str(out)]) == EXIT_DEVIATION
        assert out.is_file()
        assert "W6" in capsys.readouterr().err

    def test_unusable_report_exits_2_not_1(self, tmp_path, capsys):
        # A broken input must not read as "the baseline deviated".
        report = tmp_path / "junit.xml"
        report.write_text("<testsuites><unclosed", encoding="utf-8")
        out = tmp_path / "findings.json"
        assert main(["--junit", str(report), "--out", str(out)]) == EXIT_UNUSABLE
        assert (
            main(["--junit", str(tmp_path / "missing.xml"), "--out", str(out)])
            == EXIT_UNUSABLE
        )

    def test_report_without_any_testcase_exits_2(self, tmp_path, capsys):
        report = _write(tmp_path, [])
        out = tmp_path / "findings.json"
        assert main(["--junit", str(report), "--out", str(out)]) == EXIT_UNUSABLE


def test_the_real_security_suite_matches_the_baseline(tmp_path):
    """Every documented weakness has a ``TestW<n>`` class in the real suite,
    and the suite defines no weakness class the baseline does not know."""
    import re
    from pathlib import Path

    source = (Path(__file__).parent / "test_efb_api.py").read_text(encoding="utf-8")
    ids = {
        f"W{n}" for n in re.findall(r"^class TestW(\d+)", source, flags=re.MULTILINE)
    }
    assert ids == set(BASELINE)

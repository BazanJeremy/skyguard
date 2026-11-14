"""
SkyGuard — findings derived from the security tests
===================================================
The EFB simulator is vulnerable on purpose. Each documented weakness has a
test class, ``TestW<n>...`` in ``tests/security/test_efb_api.py``, whose
tests pass when the weakness is demonstrated.

This module turns the JUnit report of that suite into the findings fed to
the agents, and into a gate: the run deviates from the baseline when

- a documented weakness has no test at all (the gate cannot vouch for it),
- a test of a documented weakness fails (it is no longer demonstrated),
- a ``TestW<n>`` class exists that the baseline does not document.

The baseline below is the one place the weaknesses are declared.

Exit codes: 0 baseline confirmed, 1 deviation, 2 the report is unusable.
An unexpected crash exits 2 as well, never 1.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

EXIT_OK = 0
EXIT_DEVIATION = 1
EXIT_UNUSABLE = 2

BASELINE: dict[str, dict[str, str]] = {
    "W1": {"title": "No rate limiting", "severity": "high"},
    "W2": {"title": "Hardcoded JWT secret", "severity": "critical"},
    "W3": {"title": "IDOR on flight plans", "severity": "high"},
    "W4": {"title": "Unauthenticated debug", "severity": "critical"},
    "W5": {"title": "Info disclosure in errors", "severity": "medium"},
}

_WEAKNESS_CLASS = re.compile(r"^TestW(\d+)")


class UnusableReportError(Exception):
    """The JUnit report cannot be read, or holds no test case."""


@dataclass
class GateResult:
    findings: list[dict[str, str]] = field(default_factory=list)
    deviations: list[str] = field(default_factory=list)


def expected_critical_count() -> int:
    """How many documented weaknesses are critical — the gate's reference."""
    return sum(1 for entry in BASELINE.values() if entry["severity"] == "critical")


def evaluate(junit_path: str | Path) -> GateResult:
    """Derive the findings and the deviations from a JUnit report."""
    path = Path(junit_path)
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise UnusableReportError(f"{path}: cannot read ({exc})") from exc

    cases = list(root.iter("testcase"))
    if not cases:
        raise UnusableReportError(f"{path}: no <testcase> elements found")

    # weakness id -> (class name, passed, total)
    observed: dict[str, tuple[str, int, int]] = {}
    for case in cases:
        class_name = (case.get("classname") or "").rsplit(".", 1)[-1]
        match = _WEAKNESS_CLASS.match(class_name)
        if not match:
            continue
        weakness = f"W{match.group(1)}"
        failed = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        _, passed, total = observed.get(weakness, (class_name, 0, 0))
        if not skipped:
            observed[weakness] = (class_name, passed + (0 if failed else 1), total + 1)
        else:
            observed.setdefault(weakness, (class_name, passed, total))

    result = GateResult()
    for weakness in sorted(BASELINE):
        entry = BASELINE[weakness]
        class_name, passed, total = observed.get(weakness, ("", 0, 0))
        if total == 0:
            result.deviations.append(
                f"{weakness} ({entry['title']}): no test ran for it — "
                "the gate cannot vouch for a documented weakness"
            )
            continue
        if passed < total:
            result.deviations.append(
                f"{weakness} ({entry['title']}): only {passed} of {total} tests "
                "passed — the weakness is no longer demonstrated as documented"
            )
            continue
        result.findings.append(
            {
                "id": weakness,
                "title": entry["title"],
                "severity": entry["severity"],
                "evidence": f"{class_name}: {passed}/{total} tests passed",
            }
        )

    for weakness in sorted(set(observed) - set(BASELINE)):
        class_name = observed[weakness][0]
        result.deviations.append(
            f"{weakness} ({class_name}): tested but not in the baseline — "
            "document the weakness before it ships"
        )
    return result


def _run(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.gate.findings",
        description="Derive security findings from a JUnit report and gate on the baseline.",
    )
    parser.add_argument("--junit", required=True, help="JUnit XML of tests/security")
    parser.add_argument("--out", required=True, help="where to write findings.json")
    args = parser.parse_args(argv)

    try:
        result = evaluate(args.junit)
    except UnusableReportError as exc:
        print(f"findings gate: error: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE

    Path(args.out).write_text(json.dumps(result.findings, indent=2), encoding="utf-8")
    print(
        f"findings gate: {len(result.findings)} of {len(BASELINE)} documented weaknesses demonstrated"
    )
    if result.deviations:
        for deviation in result.deviations:
            print(f"findings gate: DEVIATION — {deviation}", file=sys.stderr)
        return EXIT_DEVIATION
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    try:
        return _run(argv)
    except Exception:
        traceback.print_exc()
        print("findings gate: internal error (see traceback above)", file=sys.stderr)
        return EXIT_UNUSABLE


if __name__ == "__main__":
    sys.exit(main())

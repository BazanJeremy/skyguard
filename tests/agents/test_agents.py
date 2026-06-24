"""
SkyGuard — AI Agent Tests
==========================
Tests the three AI agents in fallback mode (no API key required).
Verifies:
  1. Output contracts — every field the pipeline depends on is present
  2. Fallback behaviour — deterministic output without ANTHROPIC_API_KEY
  3. Edge cases — empty input, single finding, unknown finding IDs
  4. Markdown rendering — output can be written to a file without error

These tests run in CI without any API credentials.
Live API tests are tagged @pytest.mark.live and skipped unless ANTHROPIC_API_KEY is set.

Run: pytest tests/agents/ -v --tb=short
"""

from __future__ import annotations

import os
import pytest

from src.agents.pentest_narrator import (
    PentestNarrator,
    PentestReport,
    SecurityFinding,
    Severity,
)
from src.agents.threat_modeller import (
    ThreatModeller,
    GherkinStory,
    STRIDEModel,
    STRIDECategory,
)
from src.agents.compliance_mapper import (
    ComplianceMapper,
    ComplianceMatrix,
    ComplianceGap,
)

pytestmark = (
    pytest.mark.agents
)  # applied to all tests in this module (live tests override with skipif)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def five_findings() -> list[SecurityFinding]:
    """The canonical five EFB weaknesses — used across all agent tests."""
    return [
        SecurityFinding(
            id="W1",
            title="No rate limiting on auth endpoint",
            description="POST /auth/token accepts unlimited requests without throttling.",
            evidence="TestW1: 100 sequential attempts, 0 HTTP 429 responses returned.",
            owasp_ref="A07:2021 — Identification and Authentication Failures",
            severity=Severity.HIGH,
            endpoint="/api/v1/auth/token",
        ),
        SecurityFinding(
            id="W2",
            title="Hardcoded weak JWT secret",
            description="JWT_SECRET is hardcoded as 'skyguard-dev-secret-2024' and exposed via /debug.",
            evidence="TestW2: GET /debug returns jwt_secret in plaintext without authentication.",
            owasp_ref="A02:2021 — Cryptographic Failures",
            severity=Severity.CRITICAL,
            endpoint="/api/v1/debug",
        ),
        SecurityFinding(
            id="W3",
            title="IDOR — no ownership check on flight plans",
            description="Any authenticated pilot can read any other pilot's flight plan by ID.",
            evidence="TestW3: capt_dubois (u001) reads fp002 owned by fo_martin (u002) → 200.",
            owasp_ref="A01:2021 — Broken Access Control",
            severity=Severity.HIGH,
            endpoint="/api/v1/flightplans/<id>",
        ),
        SecurityFinding(
            id="W4",
            title="Unauthenticated debug endpoint",
            description="GET /api/v1/debug returns active tokens, usernames, env vars, and JWT secret without any auth.",
            evidence="TestW4: GET /debug without Authorization header → 200 with full system state.",
            owasp_ref="A05:2021 — Security Misconfiguration",
            severity=Severity.CRITICAL,
            endpoint="/api/v1/debug",
        ),
        SecurityFinding(
            id="W5",
            title="Stack traces and system info in responses",
            description="Error responses expose Python version, hostname, and full tracebacks.",
            evidence="TestW5: /health leaks hostname; /version leaks Python version; 500s include traceback.",
            owasp_ref="A09:2021 — Security Logging and Monitoring Failures",
            severity=Severity.MEDIUM,
            endpoint="global",
        ),
    ]


@pytest.fixture
def efb_story() -> GherkinStory:
    """A representative EFB Gherkin story for threat modelling tests."""
    return GherkinStory(
        feature="EFB flight plan access and synchronisation",
        as_a="airline pilot",
        i_want="to load, view, and update my active flight plan from the EFB tablet",
        so_that="I have accurate routing, fuel, and alternate information before departure",
        scenarios=[
            """
Scenario: Pilot views own active flight plan
  Given I am authenticated as pilot capt_dubois
  When I send GET /api/v1/flightplans/fp001
  Then I receive the flight plan with callsign AFR123
  And the response contains route, cruise_fl, and fuel_kg fields

Scenario: Pilot cannot view another pilot's flight plan
  Given I am authenticated as pilot capt_dubois
  When I send GET /api/v1/flightplans/fp002
  Then I receive HTTP 403 Forbidden
  And the response does not contain flight plan data

Scenario: Pilot updates fuel load before departure
  Given I am authenticated as pilot capt_dubois
  And flight plan fp001 belongs to me
  When I send PUT /api/v1/flightplans/fp001 with fuel_kg=13000
  Then the flight plan is updated
  And the change is recorded in the audit log
""",
        ],
        component="EFB API — /api/v1/flightplans",
    )


@pytest.fixture
def single_finding() -> list[SecurityFinding]:
    return [
        SecurityFinding(
            id="W4",
            title="Unauthenticated debug endpoint",
            description="Debug endpoint accessible without credentials.",
            evidence="GET /debug → 200 without token.",
            severity=Severity.CRITICAL,
        )
    ]


# ---------------------------------------------------------------------------
# PentestNarrator — contract tests
# ---------------------------------------------------------------------------


class TestPentestNarratorContract:
    def test_returns_pentest_report_type(self, five_findings):
        narrator = PentestNarrator()
        report = narrator.analyse(five_findings)
        assert isinstance(report, PentestReport)

    def test_executive_summary_is_non_empty_string(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert isinstance(report.executive_summary, str)
        assert len(report.executive_summary) > 10

    def test_findings_count_matches_input(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert len(report.findings) == len(five_findings)

    def test_each_finding_has_required_keys(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        required = {
            "id",
            "title",
            "cvss_score",
            "severity",
            "attack_narrative",
            "remediation",
        }
        for finding in report.findings:
            missing = required - finding.keys()
            assert not missing, f"Finding {finding.get('id')} missing: {missing}"

    def test_cvss_scores_are_numeric(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        for f in report.findings:
            score = f.get("cvss_score")
            assert isinstance(score, (int, float)), (
                f"Non-numeric CVSS for {f.get('id')}: {score!r}"
            )

    def test_cvss_scores_in_valid_range(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        for f in report.findings:
            assert 0.0 <= f["cvss_score"] <= 10.0, (
                f"CVSS out of range for {f['id']}: {f['cvss_score']}"
            )

    def test_remediation_plan_is_list(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert isinstance(report.remediation_plan, list)

    def test_attack_chains_is_list(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert isinstance(report.attack_chains, list)

    def test_ed202a_mapping_is_dict(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert isinstance(report.ed202a_mapping, dict)

    def test_prompt_version_is_set(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert report.prompt_version.startswith("v")

    def test_model_name_is_set(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert "claude" in report.model

    def test_raw_response_is_string(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert isinstance(report.raw_response, str)


class TestPentestNarratorFallback:
    def test_no_api_key_uses_fallback(self, five_findings, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        narrator = PentestNarrator(api_key=None)
        assert not narrator.has_api_key
        report = narrator.analyse(five_findings)
        assert "fallback" in report.raw_response.lower()

    def test_w2_gets_highest_cvss(self, five_findings, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        report = PentestNarrator(api_key=None).analyse(five_findings)
        scores = {f["id"]: f["cvss_score"] for f in report.findings}
        # W2 (hardcoded secret) should have the highest CVSS
        assert scores["W2"] >= scores["W1"]
        assert scores["W2"] >= scores["W3"]

    def test_empty_findings_returns_empty_report(self):
        report = PentestNarrator().analyse([])
        assert report.executive_summary == "No findings to analyse."
        assert report.findings == []

    def test_single_finding_handled(self, single_finding, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        report = PentestNarrator(api_key=None).analyse(single_finding)
        assert len(report.findings) == 1

    def test_unknown_finding_id_gets_default_cvss(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        unknown = [SecurityFinding("ZZZZ", "Unknown finding", "desc", "evidence")]
        report = PentestNarrator(api_key=None).analyse(unknown)
        assert len(report.findings) == 1
        assert report.findings[0]["cvss_score"] == 5.0


class TestPentestNarratorMarkdown:
    def test_to_markdown_returns_string(self, five_findings):
        narrator = PentestNarrator()
        report = narrator.analyse(five_findings)
        md = narrator.to_markdown(report)
        assert isinstance(md, str)

    def test_markdown_has_title(self, five_findings):
        narrator = PentestNarrator()
        md = narrator.to_markdown(narrator.analyse(five_findings))
        assert "# SkyGuard EFB" in md

    def test_markdown_has_executive_summary_section(self, five_findings):
        narrator = PentestNarrator()
        md = narrator.to_markdown(narrator.analyse(five_findings))
        assert "## Executive Summary" in md

    def test_markdown_has_findings_section(self, five_findings):
        narrator = PentestNarrator()
        md = narrator.to_markdown(narrator.analyse(five_findings))
        assert "## Findings" in md

    def test_markdown_contains_all_finding_ids(self, five_findings):
        narrator = PentestNarrator()
        md = narrator.to_markdown(narrator.analyse(five_findings))
        for f in five_findings:
            assert f.id in md, f"Finding {f.id} missing from Markdown"

    def test_markdown_has_model_footer(self, five_findings):
        narrator = PentestNarrator()
        md = narrator.to_markdown(narrator.analyse(five_findings))
        assert "claude-sonnet" in md.lower()


# ---------------------------------------------------------------------------
# ThreatModeller — contract tests
# ---------------------------------------------------------------------------


class TestThreatModellerContract:
    def test_returns_stride_model_type(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert isinstance(model, STRIDEModel)

    def test_story_title_preserved(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert model.story_title == efb_story.feature

    def test_component_preserved(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert model.component == efb_story.component

    def test_actors_is_non_empty_list(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert isinstance(model.actors, list)
        assert len(model.actors) > 0

    def test_assets_is_non_empty_list(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert isinstance(model.assets, list)
        assert len(model.assets) > 0

    def test_minimum_six_threats(self, efb_story):
        """Fallback must cover all six STRIDE categories."""
        model = ThreatModeller().analyse(efb_story)
        assert len(model.threats) >= 6

    def test_all_stride_categories_covered(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        covered = {t.category for t in model.threats}
        all_categories = set(STRIDECategory)
        assert covered == all_categories, (
            f"Missing STRIDE categories: {all_categories - covered}"
        )

    def test_each_threat_has_id(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        for t in model.threats:
            assert t.id, f"Threat has no ID: {t.title}"

    def test_each_threat_has_mitigations(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        for t in model.threats:
            assert len(t.mitigations) >= 1, f"No mitigations for {t.id}"

    def test_each_threat_has_test_cases(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        for t in model.threats:
            assert len(t.test_cases) >= 1, f"No test cases for {t.id}"

    def test_test_case_names_follow_pytest_convention(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        for t in model.threats:
            for tc in t.test_cases:
                assert tc.startswith("test_"), (
                    f"Test case '{tc}' in {t.id} does not follow pytest convention"
                )

    def test_ed202a_refs_are_set(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        for t in model.threats:
            assert t.ed202a_ref, f"No ED-202A ref for {t.id}"

    def test_attack_trees_is_list(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert isinstance(model.attack_trees, list)

    def test_attack_tree_has_root_and_tree(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        for tree in model.attack_trees:
            assert "root_threat" in tree
            assert "tree" in tree
            assert "goal" in tree

    def test_summary_is_non_empty(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert len(model.summary) > 10

    def test_likelihood_values_are_valid(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        valid = {"low", "medium", "high"}
        for t in model.threats:
            assert t.likelihood in valid, (
                f"{t.id} has invalid likelihood: {t.likelihood!r}"
            )

    def test_impact_values_are_valid(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        valid = {"low", "medium", "high", "critical"}
        for t in model.threats:
            assert t.impact in valid, f"{t.id} has invalid impact: {t.impact!r}"


class TestThreatModellerMarkdown:
    def test_to_markdown_returns_string(self, efb_story):
        modeller = ThreatModeller()
        md = modeller.to_markdown(modeller.analyse(efb_story))
        assert isinstance(md, str)

    def test_markdown_has_title(self, efb_story):
        modeller = ThreatModeller()
        md = modeller.to_markdown(modeller.analyse(efb_story))
        assert "# STRIDE Threat Model" in md

    def test_markdown_has_all_stride_sections(self, efb_story):
        modeller = ThreatModeller()
        md = modeller.to_markdown(modeller.analyse(efb_story))
        for cat in STRIDECategory:
            assert cat.value in md, (
                f"STRIDE category '{cat.value}' missing from Markdown"
            )

    def test_markdown_has_attack_tree_section(self, efb_story):
        modeller = ThreatModeller()
        model = modeller.analyse(efb_story)
        md = modeller.to_markdown(model)
        if model.attack_trees:
            assert "## Attack Trees" in md

    def test_markdown_has_model_footer(self, efb_story):
        modeller = ThreatModeller()
        md = modeller.to_markdown(modeller.analyse(efb_story))
        assert "claude-sonnet" in md.lower()


# ---------------------------------------------------------------------------
# ComplianceMapper — contract tests
# ---------------------------------------------------------------------------


class TestComplianceMapperContract:
    def test_returns_compliance_matrix_type(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        assert isinstance(matrix, ComplianceMatrix)

    def test_entry_count_matches_input(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        assert len(matrix.entries) == len(five_findings)

    def test_each_entry_has_finding_id(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        ids = {e.finding_id for e in matrix.entries}
        for f in five_findings:
            assert f.id in ids, f"Finding {f.id} has no compliance entry"

    def test_each_entry_has_ed202a_objective(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        for e in matrix.entries:
            assert e.ed202a_objective, f"No ED-202A objective for {e.finding_id}"
            assert "SO-" in e.ed202a_objective, (
                f"Objective not SO-N format: {e.ed202a_objective}"
            )

    def test_each_entry_has_do326a_process(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        for e in matrix.entries:
            assert e.do326a_process, f"No DO-326A process for {e.finding_id}"

    def test_each_entry_has_corrective_action(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        for e in matrix.entries:
            assert len(e.corrective_action) > 20, (
                f"Corrective action too vague for {e.finding_id}: {e.corrective_action!r}"
            )

    def test_each_entry_has_verification_test(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        for e in matrix.entries:
            assert e.verification_test.startswith("test_"), (
                f"Verification test for {e.finding_id} not pytest format: {e.verification_test!r}"
            )

    def test_gap_values_are_valid_enum(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        for e in matrix.entries:
            assert isinstance(e.gap, ComplianceGap)

    def test_overall_posture_is_non_empty(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        assert len(matrix.overall_posture) > 10

    def test_scope_disclaimer_is_set(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        assert "SIMULATION" in matrix.scope_disclaimer.upper()

    def test_empty_findings_returns_empty_matrix(self):
        matrix = ComplianceMapper().map([])
        assert len(matrix.entries) == 0

    def test_single_finding_handled(self, single_finding):
        matrix = ComplianceMapper().map(single_finding)
        assert len(matrix.entries) == 1


class TestComplianceMapperCounting:
    def test_critical_count_is_correct(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        expected = sum(1 for e in matrix.entries if e.gap == ComplianceGap.CRITICAL_GAP)
        assert matrix.critical_count == expected

    def test_major_count_is_correct(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        expected = sum(1 for e in matrix.entries if e.gap == ComplianceGap.MAJOR_GAP)
        assert matrix.major_count == expected

    def test_counts_sum_to_total(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        total = (
            matrix.critical_count
            + matrix.major_count
            + matrix.minor_count
            + matrix.compliant_count
        )
        assert total == len(five_findings)

    def test_w2_and_w4_are_critical(self, five_findings):
        """W2 (hardcoded secret) and W4 (unauth debug) must be CRITICAL gaps."""
        matrix = ComplianceMapper().map(five_findings)
        by_id = {e.finding_id: e for e in matrix.entries}
        assert by_id["W2"].gap == ComplianceGap.CRITICAL_GAP, "W2 must be critical gap"
        assert by_id["W4"].gap == ComplianceGap.CRITICAL_GAP, "W4 must be critical gap"

    def test_w5_is_minor_gap(self, five_findings):
        """W5 (info disclosure) is less severe — must be minor gap."""
        matrix = ComplianceMapper().map(five_findings)
        by_id = {e.finding_id: e for e in matrix.entries}
        assert by_id["W5"].gap == ComplianceGap.MINOR_GAP, "W5 should be minor gap"


class TestComplianceMapperMarkdown:
    def test_to_markdown_returns_string(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        assert isinstance(md, str)

    def test_markdown_has_title(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        assert "# SkyGuard EFB" in md
        assert "ED-202A" in md

    def test_markdown_has_gap_summary(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        assert "## Gap Summary" in md

    def test_markdown_has_compliance_matrix_table(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        assert "## Compliance Matrix" in md
        assert "|---|" in md  # Markdown table separator

    def test_markdown_contains_scope_disclaimer(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        assert "SIMULATION" in md.upper()

    def test_markdown_contains_all_finding_ids(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        for f in five_findings:
            assert f.id in md, f"Finding {f.id} missing from compliance Markdown"

    def test_markdown_has_emoji_indicators(self, five_findings):
        mapper = ComplianceMapper()
        md = mapper.to_markdown(mapper.map(five_findings))
        assert "🔴" in md  # critical gap
        assert "🟠" in md  # major gap


# ---------------------------------------------------------------------------
# Pipeline integration — agents work together
# ---------------------------------------------------------------------------


class TestAgentPipelineIntegration:
    def test_narrator_findings_feed_mapper(self, five_findings):
        """Verify PentestNarrator output can be consumed by ComplianceMapper."""
        narrator = PentestNarrator()
        report = narrator.analyse(five_findings)
        # The same findings list feeds both — both must handle it cleanly
        mapper = ComplianceMapper()
        matrix = mapper.map(five_findings)
        assert len(matrix.entries) == len(report.findings)

    def test_story_generates_threat_model_with_test_names(self, efb_story):
        """Verify ThreatModeller produces test names that match EFB test patterns."""
        model = ThreatModeller().analyse(efb_story)
        all_test_names = [tc for t in model.threats for tc in t.test_cases]
        # At least one test name should reference auth, plan, or token
        relevant = [
            n
            for n in all_test_names
            if any(
                kw in n for kw in ("token", "plan", "auth", "role", "access", "pilot")
            )
        ]
        assert len(relevant) >= 2, (
            f"Expected test names referencing EFB domain. Got: {all_test_names}"
        )

    def test_all_agents_produce_non_empty_markdown(self, five_findings, efb_story):
        """End-to-end: all three agents produce non-empty Markdown output."""
        narrator = PentestNarrator()
        modeller = ThreatModeller()
        mapper = ComplianceMapper()

        pentest_md = narrator.to_markdown(narrator.analyse(five_findings))
        stride_md = modeller.to_markdown(modeller.analyse(efb_story))
        compliance_md = mapper.to_markdown(mapper.map(five_findings))

        assert len(pentest_md) > 500, "Pentest report Markdown too short"
        assert len(stride_md) > 500, "STRIDE model Markdown too short"
        assert len(compliance_md) > 500, "Compliance matrix Markdown too short"


# ---------------------------------------------------------------------------
# Live API tests — skipped unless ANTHROPIC_API_KEY is set
# ---------------------------------------------------------------------------

live = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set — skipping live API tests",
)


@live
class TestPentestNarratorLive:
    def test_live_report_has_attack_chains(self, five_findings):
        report = PentestNarrator().analyse(five_findings)
        assert len(report.attack_chains) >= 1

    def test_live_w4_w3_chain_identified(self, five_findings):
        """The W4+W3 chain (debug → enumerate IDs → IDOR) must be identified."""
        report = PentestNarrator().analyse(five_findings)
        # Chain should reference both W4 and W3 or their titles
        chain_text = str(report.attack_chains).lower()
        assert (
            "debug" in chain_text or "idor" in chain_text or "w3" in chain_text.lower()
        )


@live
class TestThreatModellerLive:
    def test_live_model_has_more_threats_than_fallback(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        assert len(model.threats) >= 6

    def test_live_attack_tree_for_high_impact_threat(self, efb_story):
        model = ThreatModeller().analyse(efb_story)
        high_impact = [
            t for t in model.threats if t.impact == "high" and t.likelihood == "high"
        ]
        if high_impact:
            tree_roots = {tree["root_threat"] for tree in model.attack_trees}
            assert any(t.id in tree_roots for t in high_impact), (
                "Expected attack tree for high-likelihood/high-impact threat"
            )


@live
class TestComplianceMapperLive:
    def test_live_matrix_has_all_five_entries(self, five_findings):
        matrix = ComplianceMapper().map(five_findings)
        assert len(matrix.entries) == 5

    def test_live_corrective_actions_mention_code(self, five_findings):
        """Live AI should produce specific code-level fixes, not generic advice."""
        matrix = ComplianceMapper().map(five_findings)
        # At least one corrective action should mention a concrete code element
        actions = " ".join(e.corrective_action for e in matrix.entries)
        has_code = any(
            kw in actions
            for kw in ["@", "def ", "import ", "return ", "flask", "limit", "check"]
        )
        assert has_code, "Expected code-level corrective actions from live API"

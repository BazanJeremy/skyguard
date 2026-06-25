"""
SkyGuard — Compliance Mapper Agent
====================================
Maps security findings from EFB tests to EASA ED-202A and DO-326A objectives.

The agent's role in the QA pipeline:
  - Input  : list of SecurityFinding objects (same contract as Pentest Narrator)
  - Output : ComplianceMatrix (Markdown table + JSON)
  - Trigger: any CI run with findings, or on-demand before a release review

IMPORTANT — scope disclaimer:
  This mapper demonstrates the *logic* of ED-202A compliance mapping.
  It is NOT a formal compliance tool. Real DO-326A certification requires
  engagement with a DER / EASA-approved organisation.
  This is documented in ADR-003.

Agent responsibilities:
  1. Map each finding to the relevant ED-202A security objective (SO-1..SO-6)
  2. Identify DO-326A process gaps (Section 5 — Security Risk Assessment)
  3. Assign a compliance gap severity (compliant / minor gap / major gap / critical gap)
  4. Produce a remediation priority list ordered by regulatory impact
  5. Generate a compliance matrix table ready for a review board

Prompt version: v1.0.0
Model: claude-sonnet-4-6
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import anthropic

from src.agents.pentest_narrator import SecurityFinding


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class ComplianceGap(str, Enum):
    COMPLIANT = "compliant"
    MINOR_GAP = "minor_gap"
    MAJOR_GAP = "major_gap"
    CRITICAL_GAP = "critical_gap"


@dataclass
class ComplianceEntry:
    """One row in the compliance matrix."""

    finding_id: str
    finding_title: str
    ed202a_objective: str  # e.g. "SO-3: Maintain data integrity"
    ed202a_section: str  # e.g. "Section 5.2 — Threat Identification"
    do326a_process: str  # e.g. "5.3 — Security Risk Assessment"
    gap: ComplianceGap
    gap_rationale: str  # why this gap rating was assigned
    corrective_action: str  # what must be done to achieve compliance
    verification_test: str  # test name that would verify closure


@dataclass
class ComplianceMatrix:
    """Full compliance output — output of the Compliance Mapper agent."""

    system: str = "EFB API — SkyGuard simulation"
    standard: str = "EASA ED-202A / DO-326A"
    scope_disclaimer: str = (
        "SIMULATION ONLY — not a formal compliance assessment. "
        "Real certification requires engagement with an EASA-approved organisation."
    )
    entries: list[ComplianceEntry] = field(default_factory=list)
    overall_posture: str = ""
    critical_count: int = 0
    major_count: int = 0
    minor_count: int = 0
    compliant_count: int = 0
    raw_response: str = ""
    prompt_version: str = "v1.0.0"
    model: str = "claude-sonnet-4-6"

    def __post_init__(self) -> None:
        self.critical_count = sum(
            1 for e in self.entries if e.gap == ComplianceGap.CRITICAL_GAP
        )
        self.major_count = sum(
            1 for e in self.entries if e.gap == ComplianceGap.MAJOR_GAP
        )
        self.minor_count = sum(
            1 for e in self.entries if e.gap == ComplianceGap.MINOR_GAP
        )
        self.compliant_count = sum(
            1 for e in self.entries if e.gap == ComplianceGap.COMPLIANT
        )


# ---------------------------------------------------------------------------
# Prompt templates (versioned)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_V1 = """\
You are a senior aviation cybersecurity compliance specialist with expertise in:
- EASA ED-202A: Airworthiness Security Process Specification
- DO-326A: Airworthiness Security Methods and Considerations
- FAA AC 119-1 (equivalent US standard)
- Mapping software/API vulnerabilities to regulatory security objectives

You receive security findings from an Electronic Flight Bag (EFB) REST API
and map each one to the relevant ED-202A security objective and DO-326A process,
assigning a compliance gap rating.

ED-202A Security Objectives reference:
  SO-1: Identify cybersecurity threats and hazards
  SO-2: Define security requirements
  SO-3: Implement security controls
  SO-4: Verify security controls are effective
  SO-5: Ensure security is maintained throughout the lifecycle
  SO-6: Manage identified vulnerabilities

DO-326A process sections (simplified):
  Section 4 — Security planning
  Section 5 — Threat conditions and security risk assessment
  Section 6 — Security requirements definition
  Section 7 — Security design and implementation
  Section 8 — Security verification
  Section 9 — Security process assurance

Your output MUST be a single valid JSON object with this exact schema:
{
  "overall_posture": "<2-3 sentences: overall compliance posture assessment>",
  "entries": [
    {
      "finding_id": "<finding id>",
      "finding_title": "<title>",
      "ed202a_objective": "<SO-N: objective name>",
      "ed202a_section": "<specific ED-202A section reference>",
      "do326a_process": "<section N.N — process name>",
      "gap": "<compliant|minor_gap|major_gap|critical_gap>",
      "gap_rationale": "<why this gap rating — reference the finding evidence>",
      "corrective_action": "<what must be done — specific, actionable>",
      "verification_test": "<pytest test name that would verify closure>"
    }
  ]
}

Rules:
- Every finding must have exactly one entry.
- Gap ratings: critical_gap = finding directly violates an SO objective with safety impact;
  major_gap = significant control missing; minor_gap = partial control, improvement needed;
  compliant = finding is expected/documented and mitigated.
- corrective_action must be technically specific (e.g. "Add @limiter.limit('5/minute')
  decorator from Flask-Limiter"), not generic (e.g. "improve security").
- verification_test must follow pytest naming convention.
- Output ONLY the JSON. No markdown fences, no preamble.
"""

USER_PROMPT_TEMPLATE_V1 = """\
Map the following security findings from SkyGuard EFB API testing to
EASA ED-202A / DO-326A compliance objectives.

System under test: Electronic Flight Bag REST API (Flask/Python)
Context: Simulated avionics EFB. Classification: Type B EFB per EASA AMC 20-25.
Network connectivity: VPN at gate + ACARS datalink in-flight.

Security Findings:
{findings_json}

Generate the full compliance matrix JSON.
"""


# ---------------------------------------------------------------------------
# Fallback mapping table (no API key needed)
# ---------------------------------------------------------------------------

_FALLBACK_ENTRIES: dict[str, dict[str, Any]] = {
    "W1": {
        "ed202a_objective": "SO-3: Implement security controls",
        "ed202a_section": "Section 5.3 — Security risk assessment",
        "do326a_process": "7.2 — Authentication and access control implementation",
        "gap": ComplianceGap.MAJOR_GAP,
        "gap_rationale": (
            "No rate limiting on the authentication endpoint violates SO-3. "
            "An attacker can perform unlimited credential stuffing, directly "
            "threatening pilot identity assurance — a safety-relevant control."
        ),
        "corrective_action": (
            "Install Flask-Limiter and apply @limiter.limit('5/minute') "
            "to POST /api/v1/auth/token. Add progressive delay after 3 failures."
        ),
        "verification_test": "test_rate_limit_returns_429_after_5_attempts",
    },
    "W2": {
        "ed202a_objective": "SO-3: Implement security controls",
        "ed202a_section": "Section 7.1 — Cryptographic controls",
        "do326a_process": "7.3 — Cryptographic key management",
        "gap": ComplianceGap.CRITICAL_GAP,
        "gap_rationale": (
            "Hardcoded JWT secret 'skyguard-dev-secret-2024' is exposed via "
            "the debug endpoint. A compromised secret allows unlimited token forgery, "
            "enabling any attacker to impersonate any pilot — critical safety impact."
        ),
        "corrective_action": (
            "Move JWT_SECRET to environment variable loaded from a secrets vault "
            "(e.g. HashiCorp Vault or AWS Secrets Manager). "
            "Rotate the secret immediately. Remove /debug from all deployments."
        ),
        "verification_test": "test_jwt_secret_not_exposed_in_any_endpoint",
    },
    "W3": {
        "ed202a_objective": "SO-3: Implement security controls",
        "ed202a_section": "Section 6.2 — Security requirements for data integrity",
        "do326a_process": "7.2 — Authorisation and access control",
        "gap": ComplianceGap.MAJOR_GAP,
        "gap_rationale": (
            "IDOR on GET /flightplans/<id> allows any pilot to read any other pilot's "
            "flight plan. Flight plan data includes route, fuel load, and alternates — "
            "tampering could lead to a pilot operating with incorrect routing data."
        ),
        "corrective_action": (
            "Add ownership check: if plan.owner_id != current_user.id "
            "and current_user.role != 'dispatcher': return 403. "
            "Apply to GET, PUT, and DELETE endpoints."
        ),
        "verification_test": "test_pilot_cannot_access_other_pilots_plan",
    },
    "W4": {
        "ed202a_objective": "SO-3: Implement security controls",
        "ed202a_section": "Section 5.4 — Attack surface reduction",
        "do326a_process": "8.1 — Security verification of implemented controls",
        "gap": ComplianceGap.CRITICAL_GAP,
        "gap_rationale": (
            "The unauthenticated /debug endpoint exposes active session tokens, "
            "all usernames, environment variables, and the JWT secret. "
            "This single endpoint negates all other authentication controls — "
            "equivalent to leaving the cockpit door unlocked."
        ),
        "corrective_action": (
            "Remove the /debug endpoint entirely. If debugging is needed in dev, "
            "gate it behind FLASK_ENV == 'development' AND require_auth. "
            "Add Bandit rule B105 to block hardcoded secrets in CI."
        ),
        "verification_test": "test_debug_endpoint_does_not_exist_in_production",
    },
    "W5": {
        "ed202a_objective": "SO-6: Manage identified vulnerabilities",
        "ed202a_section": "Section 5.5 — Information disclosure risk",
        "do326a_process": "9.1 — Vulnerability management",
        "gap": ComplianceGap.MINOR_GAP,
        "gap_rationale": (
            "Stack traces, Python version, and hostname in responses aid targeted "
            "exploitation but do not directly enable a safety-relevant attack. "
            "Classified as minor gap — reduces attack difficulty rather than "
            "creating a primary vulnerability."
        ),
        "corrective_action": (
            "Replace global exception handler to return only {error_id: uuid} "
            "without traceback. Remove 'python' and 'system' fields from /version. "
            "Remove 'system' field from /health."
        ),
        "verification_test": "test_500_response_contains_no_traceback",
    },
}


def _fallback_matrix(findings: list[SecurityFinding]) -> ComplianceMatrix:
    """Rule-based fallback — deterministic, no API call needed."""
    entries = []
    for f in findings:
        fb = _FALLBACK_ENTRIES.get(f.id)
        if fb:
            entries.append(
                ComplianceEntry(
                    finding_id=f.id,
                    finding_title=f.title,
                    ed202a_objective=fb["ed202a_objective"],
                    ed202a_section=fb["ed202a_section"],
                    do326a_process=fb["do326a_process"],
                    gap=fb["gap"],
                    gap_rationale=fb["gap_rationale"],
                    corrective_action=fb["corrective_action"],
                    verification_test=fb["verification_test"],
                )
            )
        else:
            # Generic entry for unknown findings
            entries.append(
                ComplianceEntry(
                    finding_id=f.id,
                    finding_title=f.title,
                    ed202a_objective="SO-6: Manage identified vulnerabilities",
                    ed202a_section="Section 5.3 — Security risk assessment",
                    do326a_process="9.1 — Vulnerability management",
                    gap=ComplianceGap.MAJOR_GAP,
                    gap_rationale=f.description,
                    corrective_action="Assess and remediate per security risk assessment.",
                    verification_test=f"test_{f.id.lower()}_remediated",
                )
            )

    matrix = ComplianceMatrix(
        entries=entries, raw_response="[fallback — no API call made]"
    )
    matrix.overall_posture = (
        f"Rule-based assessment (no API key). "
        f"{matrix.critical_count} critical gap(s), {matrix.major_count} major gap(s), "
        f"{matrix.minor_count} minor gap(s) across {len(entries)} finding(s). "
        f"Critical gaps must be resolved before any deployment of the EFB system."
    )
    return matrix


# ---------------------------------------------------------------------------
# Compliance Mapper Agent
# ---------------------------------------------------------------------------


class ComplianceMapper:
    """
    AI agent that maps security findings to EASA ED-202A / DO-326A objectives.

    Usage:
        mapper = ComplianceMapper()
        matrix = mapper.map(findings)
        print(mapper.to_markdown(matrix))
    """

    def __init__(
        self, api_key: str | None = None, model: str = "claude-sonnet-4-6"
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._model = model
        self._client = (
            anthropic.Anthropic(api_key=self._api_key) if self._api_key else None
        )

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    def map(self, findings: list[SecurityFinding]) -> ComplianceMatrix:
        """Map findings to compliance objectives. Uses AI if key available."""
        if not findings:
            return ComplianceMatrix(overall_posture="No findings to assess.")

        if not self.has_api_key:
            return _fallback_matrix(findings)

        return self._call_api(findings)

    def _call_api(self, findings: list[SecurityFinding]) -> ComplianceMatrix:
        from dataclasses import asdict

        findings_json = json.dumps([asdict(f) for f in findings], indent=2, default=str)
        user_prompt = USER_PROMPT_TEMPLATE_V1.format(findings_json=findings_json)

        assert self._client is not None, "_call_api requires a valid API key"
        message = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=SYSTEM_PROMPT_V1,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text_block = next(b for b in message.content if b.type == "text")
        raw = text_block.text.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        parsed = json.loads(raw)

        entries = []
        for e in parsed.get("entries", []):
            try:
                gap = ComplianceGap(e.get("gap", "major_gap"))
            except ValueError:
                gap = ComplianceGap.MAJOR_GAP
            entries.append(
                ComplianceEntry(
                    finding_id=e.get("finding_id", "?"),
                    finding_title=e.get("finding_title", ""),
                    ed202a_objective=e.get("ed202a_objective", ""),
                    ed202a_section=e.get("ed202a_section", ""),
                    do326a_process=e.get("do326a_process", ""),
                    gap=gap,
                    gap_rationale=e.get("gap_rationale", ""),
                    corrective_action=e.get("corrective_action", ""),
                    verification_test=e.get("verification_test", ""),
                )
            )

        matrix = ComplianceMatrix(
            entries=entries,
            overall_posture=parsed.get("overall_posture", ""),
            raw_response=raw,
            model=self._model,
        )
        return matrix

    def to_markdown(self, matrix: ComplianceMatrix) -> str:
        """Render a ComplianceMatrix as a Markdown compliance report."""
        gap_emoji = {
            ComplianceGap.CRITICAL_GAP: "🔴",
            ComplianceGap.MAJOR_GAP: "🟠",
            ComplianceGap.MINOR_GAP: "🟡",
            ComplianceGap.COMPLIANT: "🟢",
        }

        lines = [
            "# SkyGuard EFB — ED-202A / DO-326A Compliance Matrix",
            "",
            f"> ⚠️ **{matrix.scope_disclaimer}**",
            "",
            f"**Standard:** {matrix.standard}  ",
            f"**System:** {matrix.system}  ",
            f"**Prompt version:** {matrix.prompt_version} · **Model:** {matrix.model}",
            "",
            "## Overall Posture",
            "",
            matrix.overall_posture,
            "",
            "## Gap Summary",
            "",
            "| Gap level | Count |",
            "|---|---|",
            f"| 🔴 Critical gap | {matrix.critical_count} |",
            f"| 🟠 Major gap    | {matrix.major_count} |",
            f"| 🟡 Minor gap    | {matrix.minor_count} |",
            f"| 🟢 Compliant    | {matrix.compliant_count} |",
            "",
            "## Compliance Matrix",
            "",
            "| Finding | Title | ED-202A Objective | DO-326A Process | Gap |",
            "|---|---|---|---|---|",
        ]

        for e in matrix.entries:
            emoji = gap_emoji.get(e.gap, "⚪")
            gap_label = e.gap.value.replace("_", " ").title()
            lines.append(
                f"| `{e.finding_id}` | {e.finding_title} | {e.ed202a_objective} "
                f"| {e.do326a_process} | {emoji} {gap_label} |"
            )

        lines += ["", "## Detailed Findings", ""]

        for e in matrix.entries:
            emoji = gap_emoji.get(e.gap, "⚪")
            lines += [
                f"### {e.finding_id} — {e.finding_title}",
                "",
                f"- **ED-202A Objective:** {e.ed202a_objective}",
                f"- **ED-202A Section:** {e.ed202a_section}",
                f"- **DO-326A Process:** {e.do326a_process}",
                f"- **Gap:** {emoji} {e.gap.value.replace('_', ' ').title()}",
                "",
                f"**Rationale:** {e.gap_rationale}",
                "",
                f"**Corrective action:** {e.corrective_action}",
                "",
                f"**Verification test:** `{e.verification_test}`",
                "",
            ]

        lines += [
            "---",
            f"*Generated by SkyGuard Compliance Mapper · "
            f"Prompt v{matrix.prompt_version} · Model: {matrix.model}*",
        ]

        return "\n".join(lines)

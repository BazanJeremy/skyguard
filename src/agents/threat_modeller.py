"""
SkyGuard — Threat Modeller Agent
==================================
Reads a User Story in Gherkin format and produces a complete STRIDE
threat model with ED-202A mapping.

The agent's role in the QA pipeline:
  - Input  : GherkinStory (feature + scenarios)
  - Output : STRIDEModel (JSON + Markdown)
  - Trigger: PR creation when a new feature story is added

This agent performs:
  1. Actor and asset extraction from Gherkin scenarios
  2. STRIDE threat enumeration per actor/asset pair
  3. Attack tree generation for high-severity threats
  4. Mitigations mapped to concrete test cases
  5. ED-202A objective cross-reference

Prompt version: v1.0.0
Model: claude-sonnet-4-6
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum

import anthropic


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class GherkinStory:
    """Input: a User Story with Gherkin scenarios."""

    feature: str  # Feature title
    as_a: str  # Actor
    i_want: str  # Goal
    so_that: str  # Benefit
    scenarios: list[str]  # Raw Gherkin scenario text blocks
    component: str = ""  # System component (e.g. "EFB API", "ARINC 429 bus")


@dataclass
class STRIDEThreat:
    """One identified STRIDE threat."""

    id: str
    category: STRIDECategory
    title: str
    description: str
    asset: str  # what is at risk
    actor: str  # who performs the attack
    likelihood: str  # low / medium / high
    impact: str  # low / medium / high
    ed202a_ref: str  # ED-202A objective reference
    mitigations: list[str]  # concrete defensive measures
    test_cases: list[str]  # suggested Pytest/Playwright test names


@dataclass
class STRIDEModel:
    """Full STRIDE threat model — output of the Threat Modeller agent."""

    story_title: str
    component: str
    actors: list[str]
    assets: list[str]
    threats: list[STRIDEThreat]
    attack_trees: list[dict]  # for high-severity threats
    summary: str
    raw_response: str
    prompt_version: str = "v1.0.0"
    model: str = "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# Prompt templates (versioned)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_V1 = """\
You are a senior aviation cybersecurity architect specialised in threat modelling
for airborne systems. You have deep knowledge of:
- STRIDE threat modelling methodology
- EASA ED-202A Airworthiness Security Process Specification
- DO-326A Airworthiness Security Methods and Considerations
- Common avionics attack patterns (EFB, ACARS, ADS-B, ARINC 429)

You receive a User Story in Gherkin format describing a feature of an
Electronic Flight Bag (EFB) avionics system and produce a complete STRIDE
threat model.

Your output MUST be a single valid JSON object with this exact schema:
{
  "actors": ["<list of actors extracted from the story>"],
  "assets": ["<list of assets/data identified in the story>"],
  "summary": "<2-3 sentence overview of the threat landscape for this feature>",
  "threats": [
    {
      "id": "T-<number>",
      "category": "<Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege>",
      "title": "<short threat title>",
      "description": "<what the threat is and how it manifests in this specific context>",
      "asset": "<which asset is targeted>",
      "actor": "<who performs this attack>",
      "likelihood": "<low|medium|high>",
      "impact": "<low|medium|high>",
      "ed202a_ref": "<relevant ED-202A objective, e.g. 'SO-1: Identify cybersecurity threats'>",
      "mitigations": ["<specific, actionable mitigation 1>", "<mitigation 2>"],
      "test_cases": ["<suggested test name 1>", "<suggested test name 2>"]
    }
  ],
  "attack_trees": [
    {
      "root_threat": "<T-id of the high/critical threat>",
      "goal": "<attacker goal>",
      "tree": {
        "node": "<root attack step>",
        "children": [
          {"node": "<step>", "children": []},
          {"node": "<step>", "children": []}
        ]
      }
    }
  ]
}

Rules:
- Produce at least one threat per STRIDE category (6 minimum).
- Include an attack tree for every threat rated high likelihood AND high impact.
- Test case names must follow pytest naming convention (test_<verb>_<subject>).
- ED-202A references must be specific (SO-1 through SO-6 or objective names from the spec).
- Output ONLY the JSON. No markdown fences, no preamble.
"""

USER_PROMPT_TEMPLATE_V1 = """\
Produce a STRIDE threat model for the following User Story from the SkyGuard EFB system.

System: Electronic Flight Bag REST API — used by airline pilots for flight planning,
datalink messaging, and performance calculations.

User Story:
  Feature: {feature}
  As a {as_a}
  I want {i_want}
  So that {so_that}

Component: {component}

Gherkin Scenarios:
{scenarios}

Generate the complete STRIDE threat model JSON.
"""


# ---------------------------------------------------------------------------
# Fallback — rule-based STRIDE skeleton (no API key needed)
# ---------------------------------------------------------------------------

_STRIDE_FALLBACK_THREATS = [
    (
        "S",
        STRIDECategory.SPOOFING,
        "Actor identity spoofing",
        "An attacker impersonates a legitimate pilot or dispatcher to gain access.",
        "User identity",
        "External attacker",
        "medium",
        "high",
        "SO-2: Protect against identity spoofing",
        ["Implement MFA for pilot login", "Validate token signature on every request"],
        ["test_fake_token_rejected", "test_expired_token_rejected"],
    ),
    (
        "T",
        STRIDECategory.TAMPERING,
        "Flight plan data tampering",
        "An authenticated user modifies another pilot's flight plan via IDOR.",
        "Flight plan data",
        "Malicious insider / compromised account",
        "high",
        "high",
        "SO-3: Maintain data integrity",
        [
            "Add ownership check before any plan mutation",
            "Log all write operations with user ID",
        ],
        ["test_pilot_cannot_modify_others_plan", "test_ownership_enforced_on_delete"],
    ),
    (
        "R",
        STRIDECategory.REPUDIATION,
        "Audit log bypass",
        "No request logging means actions cannot be attributed to a specific user.",
        "Audit trail",
        "Any authenticated user",
        "medium",
        "medium",
        "SO-4: Support non-repudiation",
        [
            "Implement structured request logging (user_id, endpoint, timestamp, response_code)",
            "Store logs in append-only storage",
        ],
        ["test_action_logged_on_flight_plan_create", "test_auth_attempt_logged"],
    ),
    (
        "I",
        STRIDECategory.INFORMATION_DISCLOSURE,
        "Debug endpoint data exposure",
        "Unauthenticated /debug endpoint exposes JWT secret, active tokens, and env vars.",
        "JWT secret / session tokens",
        "External attacker",
        "high",
        "critical",
        "SO-5: Prevent information disclosure",
        [
            "Remove /debug endpoint from production",
            "Move sensitive config to environment vault",
        ],
        ["test_debug_returns_403_in_production", "test_jwt_secret_not_in_any_response"],
    ),
    (
        "D",
        STRIDECategory.DENIAL_OF_SERVICE,
        "Brute-force authentication flood",
        "No rate limiting on /auth/token allows credential stuffing at scale.",
        "Authentication service",
        "External attacker",
        "high",
        "high",
        "SO-6: Maintain availability",
        [
            "Add rate limiting: max 5 attempts/minute per IP",
            "Implement progressive delay",
        ],
        [
            "test_rate_limit_returns_429_after_5_attempts",
            "test_lockout_after_threshold",
        ],
    ),
    (
        "E",
        STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "Role escalation via token replay",
        "Tokens do not encode role at issuance; role is re-fetched from mutable store.",
        "Role-based access control",
        "Compromised user account",
        "low",
        "high",
        "SO-2: Protect against privilege escalation",
        ["Embed role in signed token payload", "Invalidate tokens on role change"],
        [
            "test_role_change_invalidates_existing_token",
            "test_pilot_token_rejected_on_maintenance_route",
        ],
    ),
]


def _fallback_model(story: GherkinStory) -> STRIDEModel:
    threats = []
    for i, (
        short,
        cat,
        title,
        desc,
        asset,
        actor,
        likelihood,
        impact,
        ed,
        mitigations,
        tests,
    ) in enumerate(_STRIDE_FALLBACK_THREATS, start=1):
        threats.append(
            STRIDEThreat(
                id=f"T-{i:02d}",
                category=cat,
                title=title,
                description=desc,
                asset=asset,
                actor=actor,
                likelihood=likelihood,
                impact=impact,
                ed202a_ref=ed,
                mitigations=mitigations,
                test_cases=tests,
            )
        )

    return STRIDEModel(
        story_title=story.feature,
        component=story.component or "EFB API",
        actors=[
            "Pilot",
            "Dispatcher",
            "Maintenance technician",
            "External attacker",
            "Malicious insider",
        ],
        assets=[
            "Flight plan data",
            "User credentials",
            "JWT tokens",
            "Audit logs",
            "System configuration",
        ],
        threats=threats,
        attack_trees=[
            {
                "root_threat": "T-02",
                "goal": "Read or modify another pilot's flight plan",
                "tree": {
                    "node": "Access any flight plan via IDOR",
                    "children": [
                        {
                            "node": "Obtain valid Bearer token (legitimate login or credential stuffing)",
                            "children": [],
                        },
                        {
                            "node": "Enumerate plan IDs (sequential: fp001, fp002...)",
                            "children": [
                                {
                                    "node": "Use /debug to get all plan IDs without auth",
                                    "children": [],
                                }
                            ],
                        },
                        {
                            "node": "GET /flightplans/<id> — no ownership check → 200",
                            "children": [],
                        },
                    ],
                },
            }
        ],
        summary=(
            f"Rule-based STRIDE model for '{story.feature}' (no API key). "
            "6 threats identified covering all STRIDE categories. "
            "Run with ANTHROPIC_API_KEY for full AI threat analysis."
        ),
        raw_response="[fallback — no API call made]",
    )


# ---------------------------------------------------------------------------
# Threat Modeller Agent
# ---------------------------------------------------------------------------


class ThreatModeller:
    """
    AI agent that reads a Gherkin User Story and produces a STRIDE threat model.

    Usage:
        story = GherkinStory(
            feature="EFB flight plan synchronisation",
            as_a="pilot",
            i_want="to load and update my flight plan from the EFB",
            so_that="I have accurate routing information before departure",
            scenarios=[scenario_text],
            component="EFB API — /api/v1/flightplans",
        )
        modeller = ThreatModeller()
        model = modeller.analyse(story)
        print(modeller.to_markdown(model))
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

    def analyse(self, story: GherkinStory) -> STRIDEModel:
        if not self.has_api_key:
            return _fallback_model(story)
        return self._call_api(story)

    def _call_api(self, story: GherkinStory) -> STRIDEModel:
        scenarios_text = "\n\n".join(story.scenarios)
        user_prompt = USER_PROMPT_TEMPLATE_V1.format(
            feature=story.feature,
            as_a=story.as_a,
            i_want=story.i_want,
            so_that=story.so_that,
            component=story.component,
            scenarios=scenarios_text,
        )

        message = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=SYSTEM_PROMPT_V1,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw = message.content[0].text.strip()

        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()

        parsed = json.loads(raw)

        threats = []
        for t in parsed.get("threats", []):
            threats.append(
                STRIDEThreat(
                    id=t.get("id", "T-?"),
                    category=STRIDECategory(t.get("category", "Tampering")),
                    title=t.get("title", ""),
                    description=t.get("description", ""),
                    asset=t.get("asset", ""),
                    actor=t.get("actor", ""),
                    likelihood=t.get("likelihood", "medium"),
                    impact=t.get("impact", "medium"),
                    ed202a_ref=t.get("ed202a_ref", ""),
                    mitigations=t.get("mitigations", []),
                    test_cases=t.get("test_cases", []),
                )
            )

        return STRIDEModel(
            story_title=story.feature,
            component=story.component,
            actors=parsed.get("actors", []),
            assets=parsed.get("assets", []),
            threats=threats,
            attack_trees=parsed.get("attack_trees", []),
            summary=parsed.get("summary", ""),
            raw_response=raw,
            model=self._model,
        )

    def to_markdown(self, model: STRIDEModel) -> str:
        """Render a STRIDEModel as a Markdown threat model document."""
        lines = [
            f"# STRIDE Threat Model — {model.story_title}",
            "",
            f"**Component:** {model.component}",
            f"**Prompt version:** {model.prompt_version} · **Model:** {model.model}",
            "",
            "## Overview",
            "",
            model.summary,
            "",
            f"**Actors:** {', '.join(model.actors)}",
            f"**Assets at risk:** {', '.join(model.assets)}",
            "",
            "## Threats",
            "",
        ]

        # Group by STRIDE category
        by_category: dict[str, list[STRIDEThreat]] = {}
        for threat in model.threats:
            by_category.setdefault(threat.category.value, []).append(threat)

        stride_order = [c.value for c in STRIDECategory]
        for cat in stride_order:
            cat_threats = by_category.get(cat, [])
            if not cat_threats:
                continue
            lines += [f"### {cat}", ""]
            for t in cat_threats:
                badge = (
                    f"`{t.likelihood.upper()} likelihood / {t.impact.upper()} impact`"
                )
                lines += [
                    f"#### {t.id} — {t.title}",
                    "",
                    f"{badge}",
                    "",
                    f"**Asset:** {t.asset}  ",
                    f"**Actor:** {t.actor}  ",
                    f"**ED-202A:** {t.ed202a_ref}",
                    "",
                    t.description,
                    "",
                    "**Mitigations:**",
                ]
                for m in t.mitigations:
                    lines.append(f"- {m}")
                lines += [
                    "",
                    "**Suggested test cases:**",
                ]
                for tc in t.test_cases:
                    lines.append(f"- `{tc}`")
                lines.append("")

        if model.attack_trees:
            lines += ["## Attack Trees", ""]
            for tree in model.attack_trees:
                lines += [
                    f"### {tree.get('root_threat')} — {tree.get('goal')}",
                    "",
                    "```",
                    _render_tree(tree.get("tree", {})),
                    "```",
                    "",
                ]

        lines += [
            "---",
            f"*Generated by SkyGuard Threat Modeller · Prompt v{model.prompt_version} · Model: {model.model}*",
        ]
        return "\n".join(lines)


def _render_tree(node: dict, indent: int = 0) -> str:
    """Recursively render an attack tree as ASCII art."""
    prefix = "  " * indent + ("└─ " if indent > 0 else "")
    lines = [prefix + node.get("node", "?")]
    for child in node.get("children", []):
        lines.append(_render_tree(child, indent + 1))
    return "\n".join(lines)

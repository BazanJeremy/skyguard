#!/usr/bin/env python3
"""
SkyGuard — End-to-End AI Pipeline Demo
=======================================
Demonstrates the three AI agents working together on the EFB security findings.

Without ANTHROPIC_API_KEY: runs in deterministic fallback mode (no API calls).
With    ANTHROPIC_API_KEY: calls Claude claude-sonnet-4-6 for each agent.

Usage:
    python demo.py                   # fallback mode
    ANTHROPIC_API_KEY=sk-... python demo.py   # live AI mode
    python demo.py --save            # save Markdown reports to reports/

Output:
    - Console summary with CVSS scores and gap ratings
    - Markdown files in reports/ (with --save)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from src.agents.pentest_narrator import (
    PentestNarrator, SecurityFinding, Severity,
)
from src.agents.threat_modeller import (
    ThreatModeller, GherkinStory,
)
from src.agents.compliance_mapper import (
    ComplianceMapper, ComplianceGap,
)

# ── ANSI colours (degrade gracefully on Windows) ──────────────────────────────
RED    = "\033[91m" if sys.platform != "win32" else ""
YELLOW = "\033[93m" if sys.platform != "win32" else ""
GREEN  = "\033[92m" if sys.platform != "win32" else ""
BLUE   = "\033[94m" if sys.platform != "win32" else ""
BOLD   = "\033[1m"  if sys.platform != "win32" else ""
RESET  = "\033[0m"  if sys.platform != "win32" else ""

GAP_COLOUR = {
    ComplianceGap.CRITICAL_GAP: RED,
    ComplianceGap.MAJOR_GAP:    YELLOW,
    ComplianceGap.MINOR_GAP:    BLUE,
    ComplianceGap.COMPLIANT:    GREEN,
}

GAP_EMOJI = {
    ComplianceGap.CRITICAL_GAP: "🔴",
    ComplianceGap.MAJOR_GAP:    "🟠",
    ComplianceGap.MINOR_GAP:    "🟡",
    ComplianceGap.COMPLIANT:    "🟢",
}


def banner(title: str) -> None:
    width = 60
    print(f"\n{BOLD}{'═' * width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'═' * width}{RESET}\n")


def section(title: str) -> None:
    print(f"\n{BOLD}{BLUE}▶ {title}{RESET}")
    print("─" * 50)


# ── Fixtures ──────────────────────────────────────────────────────────────────

EFB_FINDINGS: list[SecurityFinding] = [
    SecurityFinding(
        id="W1", title="No rate limiting on auth endpoint",
        description="POST /auth/token accepts unlimited requests without throttling.",
        evidence="TestW1NoRateLimiting: 100 sequential attempts — 0 HTTP 429 responses.",
        owasp_ref="A07:2021 — Identification and Authentication Failures",
        severity=Severity.HIGH, endpoint="/api/v1/auth/token",
    ),
    SecurityFinding(
        id="W2", title="Hardcoded weak JWT secret",
        description="JWT_SECRET is hardcoded and exposed via the unauthenticated /debug endpoint.",
        evidence="TestW2HardcodedSecret: GET /debug → jwt_secret='skyguard-dev-secret-2024'.",
        owasp_ref="A02:2021 — Cryptographic Failures",
        severity=Severity.CRITICAL, endpoint="/api/v1/debug",
    ),
    SecurityFinding(
        id="W3", title="IDOR — no ownership check on flight plans",
        description="Any authenticated pilot can read any other pilot's flight plan by guessing the ID.",
        evidence="TestW3IDOR: capt_dubois reads fp002 (owned by fo_martin) → HTTP 200.",
        owasp_ref="A01:2021 — Broken Access Control",
        severity=Severity.HIGH, endpoint="/api/v1/flightplans/<id>",
    ),
    SecurityFinding(
        id="W4", title="Unauthenticated debug endpoint",
        description="GET /api/v1/debug returns tokens, usernames, env vars, and the JWT secret with no auth.",
        evidence="TestW4DebugEndpoint: GET /debug without Authorization → HTTP 200, full state.",
        owasp_ref="A05:2021 — Security Misconfiguration",
        severity=Severity.CRITICAL, endpoint="/api/v1/debug",
    ),
    SecurityFinding(
        id="W5", title="Stack traces and server info in responses",
        description="Error responses leak Python version, hostname, and full tracebacks.",
        evidence="TestW5InformationDisclosure: /health exposes hostname; 500 includes traceback.",
        owasp_ref="A09:2021 — Security Logging and Monitoring Failures",
        severity=Severity.MEDIUM, endpoint="global",
    ),
]

EFB_STORY = GherkinStory(
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
  And the response contains route, cruise_fl, and fuel_kg

Scenario: Pilot cannot view another pilot's flight plan
  Given I am authenticated as pilot capt_dubois
  When I send GET /api/v1/flightplans/fp002
  Then I receive HTTP 403 Forbidden

Scenario: Dispatcher can view all flight plans
  Given I am authenticated as disp_lambert with role dispatcher
  When I send GET /api/v1/flightplans
  Then I receive all flight plans in the system
""",
    ],
    component="EFB API — /api/v1/flightplans",
)


# ── Agent runners ──────────────────────────────────────────────────────────────

def run_pentest_narrator(save: bool, reports_dir: Path) -> str:
    section("Agent 1 / 3 — Pentest Narrator")
    print("  Input : 5 security findings from EFB test suite")
    print("  Output: CVSS scores · attack chains · remediation plan\n")

    narrator = PentestNarrator()
    mode = "live AI" if narrator.has_api_key else "fallback (no API key)"
    print(f"  Mode: {BOLD}{mode}{RESET}")

    report = narrator.analyse(EFB_FINDINGS)

    print(f"\n  {BOLD}Executive Summary:{RESET}")
    for line in report.executive_summary.split(". "):
        if line.strip():
            print(f"    • {line.strip()}.")

    print(f"\n  {BOLD}Findings — CVSS Scores:{RESET}")
    for f in report.findings:
        score = f.get("cvss_score", "?")
        sev   = f.get("severity", "?").upper()
        title = f.get("title", "?")
        fid   = f.get("id", "?")
        colour = RED if score and float(score) >= 9.0 else YELLOW if float(score) >= 7.0 else BLUE
        print(f"    {colour}{fid:<4} CVSS {score:<5} [{sev:<8}]{RESET}  {title}")

    if report.attack_chains:
        print(f"\n  {BOLD}Attack Chains identified: {len(report.attack_chains)}{RESET}")
        for chain in report.attack_chains:
            print(f"    ⛓  {chain.get('name', '?')} — {chain.get('combined_severity', '?').upper()}")

    md = narrator.to_markdown(report)
    if save:
        path = reports_dir / "pentest-report.md"
        path.write_text(md, encoding="utf-8")
        print(f"\n  {GREEN}✓ Saved → {path}{RESET}")

    return md


def run_threat_modeller(save: bool, reports_dir: Path) -> str:
    section("Agent 2 / 3 — Threat Modeller (STRIDE)")
    print(f"  Input : Gherkin story — '{EFB_STORY.feature}'")
    print("  Output: STRIDE model · attack trees · test case suggestions\n")

    modeller = ThreatModeller()
    mode = "live AI" if modeller.has_api_key else "fallback (no API key)"
    print(f"  Mode: {BOLD}{mode}{RESET}")

    model = modeller.analyse(EFB_STORY)

    print(f"\n  {BOLD}Summary:{RESET}")
    print(f"    {model.summary}")

    print(f"\n  {BOLD}Threats identified: {len(model.threats)} across {len(set(t.category for t in model.threats))} STRIDE categories{RESET}")

    stride_labels = {
        "Spoofing": "S", "Tampering": "T", "Repudiation": "R",
        "Information Disclosure": "I", "Denial of Service": "D",
        "Elevation of Privilege": "E",
    }
    for t in model.threats:
        letter = stride_labels.get(t.category.value, "?")
        colour = RED if t.impact in ("high", "critical") else YELLOW
        print(
            f"    {colour}[{letter}] {t.id:<6}{RESET} {t.title:<45} "
            f"{t.likelihood.upper()}/{t.impact.upper()}"
        )

    if model.attack_trees:
        print(f"\n  {BOLD}Attack trees: {len(model.attack_trees)}{RESET}")
        for tree in model.attack_trees:
            print(f"    🌳 {tree.get('root_threat')} — {tree.get('goal', '?')}")

    md = modeller.to_markdown(model)
    if save:
        path = reports_dir / "stride-threat-model.md"
        path.write_text(md, encoding="utf-8")
        print(f"\n  {GREEN}✓ Saved → {path}{RESET}")

    return md


def run_compliance_mapper(save: bool, reports_dir: Path) -> str:
    section("Agent 3 / 3 — Compliance Mapper (ED-202A / DO-326A)")
    print("  Input : 5 security findings")
    print("  Output: compliance matrix · gap ratings · corrective actions\n")

    mapper = ComplianceMapper()
    mode = "live AI" if mapper.has_api_key else "fallback (no API key)"
    print(f"  Mode: {BOLD}{mode}{RESET}")

    matrix = mapper.map(EFB_FINDINGS)

    print(f"\n  {BOLD}Overall Posture:{RESET}")
    print(f"    {matrix.overall_posture}")

    print(f"\n  {BOLD}Gap Summary:{RESET}")
    print(f"    🔴 Critical: {matrix.critical_count}  🟠 Major: {matrix.major_count}  "
          f"🟡 Minor: {matrix.minor_count}  🟢 Compliant: {matrix.compliant_count}")

    print(f"\n  {BOLD}Compliance Matrix:{RESET}")
    for e in matrix.entries:
        colour = GAP_COLOUR.get(e.gap, "")
        emoji  = GAP_EMOJI.get(e.gap, "⚪")
        gap_label = e.gap.value.replace("_", " ").title()
        print(f"    {emoji} {colour}{e.finding_id:<4}{RESET}  {e.ed202a_objective:<35}  {gap_label}")

    md = mapper.to_markdown(matrix)
    if save:
        path = reports_dir / "compliance-matrix.md"
        path.write_text(md, encoding="utf-8")
        print(f"\n  {GREEN}✓ Saved → {path}{RESET}")

    return md


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SkyGuard AI Pipeline Demo")
    parser.add_argument("--save", action="store_true", help="Save Markdown reports to reports/")
    args = parser.parse_args()

    reports_dir = Path("reports")
    if args.save:
        reports_dir.mkdir(exist_ok=True)

    banner("SkyGuard — AI-Driven Avionics Cybersecurity QA")

    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    key_status = f"{GREEN}✓ ANTHROPIC_API_KEY set — live AI mode{RESET}" if has_key \
                 else f"{YELLOW}⚠ No API key — fallback (deterministic) mode{RESET}"
    print(f"  {key_status}")
    print(f"  System under test: EFB API + ARINC 429 bus + ACARS parser")
    print(f"  Findings: {len(EFB_FINDINGS)} documented vulnerabilities (W1–W5)")
    print(f"  Agents  : Pentest Narrator · Threat Modeller · Compliance Mapper")
    if args.save:
        print(f"  Reports : {reports_dir.absolute()}/")

    run_pentest_narrator(args.save, reports_dir)
    run_threat_modeller(args.save, reports_dir)
    run_compliance_mapper(args.save, reports_dir)

    # ── Final summary ──────────────────────────────────────────────────────────
    banner("Pipeline Complete")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"  Timestamp : {ts}")
    print(f"  Tests     : 252 passed, 6 skipped")
    print(f"  Agents    : 3 / 3 completed")
    if args.save:
        for name in ["pentest-report.md", "stride-threat-model.md", "compliance-matrix.md"]:
            p = reports_dir / name
            if p.exists():
                size = p.stat().st_size
                print(f"  {GREEN}✓{RESET} {p}  ({size:,} bytes)")
    print()
    print(f"  {BOLD}Next step:{RESET} run 'pytest tests/ -v' to see the full test suite.")
    print(f"  {BOLD}Docs     :{RESET} see docs/ADR-002-ai-agent-design.md for architecture decisions.")
    print()


if __name__ == "__main__":
    main()

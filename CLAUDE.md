# CLAUDE.md — SkyGuard

> Avionics cybersecurity QA platform — AI-augmented security test orchestration.
> Portfolio project P2 of a 6-project AI Test Engineering portfolio.

## Project State — READ FIRST

- **Status: ✅ COMPLETE and validated in real conditions.** 252/252 tests passing locally (Windows, Python 3.14).
- Includes: **3 AI agents**, Docker packaging, **Allure reporting**, GitHub Actions CI/CD.
- This project is in **maintenance mode**. Default posture: do NOT refactor, restructure, or "improve" anything unless explicitly asked.
- If a change is requested, make the **smallest targeted fix** possible. No broad rewrites, ever.
- The Docker setup and Allure integration are validated — do not touch them unless they break.

## Environment

- OS: Windows 11, shell: PowerShell
- Python 3.14, virtualenv in `.venv`
- Run tests with: `python -m pytest` — **NEVER** bare `pytest`
- Docker Desktop available for compose runs; CI must NOT require Docker for the core test suite
- Allure results generated locally; do not read `allure-results/` or `allure-report/` folders (large, token waste)
- CI: GitHub Actions (free tier, repo private under `BazanJeremy`)

## Architecture Principles (non-negotiable, portfolio-wide)

1. **Deterministic fallback on every AI agent.** Suite and CI run green with zero API keys.
2. **Pydantic v2** for all models.
3. **ADRs in `docs/adr/`** — never edited retroactively, only superseded.
4. **Bugs found by tests = portfolio evidence** — document before fixing.

## Domain Context

- Simulated business problem: security test coverage and threat-driven test generation for avionics software components.
- Reference frameworks used in the project: **STRIDE, CVSS, OWASP Top 10, EASA ED-202A / DO-326A**. Keep terminology aligned with these standards in any doc touch-up.
- Interview narrative: cross-sector credibility — avionics rigor as a differentiator when pitching to **Banking/Fintech** (regulated, safety-adjacent) and **Health/Medtech** (safety-critical software culture).
- The 3 agents demonstrate agent specialization; do not merge or "simplify" them.

## Conventions

- Codebase, comments, README, ADRs: **professional English**.
- Conversation with the user: French.
- Commits: small, atomic, imperative English messages.
- Free/open-source tools only.
- Report exact errors, fix precisely — the user runs everything locally and pastes real output.

## What NOT to Do

- No new dependencies on a completed project.
- No README regeneration — final and senior-reviewed.
- No scanning of `.venv/`, `allure-results/`, `allure-report/`, Docker build caches.
- Do not weaken or bypass security-oriented test assertions to "make tests pass".

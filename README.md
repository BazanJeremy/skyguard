# SkyGuard — Avionics Cybersecurity QA Platform

> **Simulates the digital attack surface of a commercial aircraft and deploys three autonomous AI agents to detect threats, model risks with STRIDE, and map findings to EASA ED-202A — fully automated on every commit.**

[![CI](https://github.com/BazanJeremy/skyguard/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/BazanJeremy/skyguard/actions/workflows/security-pipeline.yml)
[![Tests](https://img.shields.io/badge/tests-252%20passing%20%7C%206%20skipped-brightgreen?logo=pytest)]()
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue?logo=python)](requirements.txt)
[![AI](https://img.shields.io/badge/AI%20agents-3%20×%20Claude%20Sonnet-8B5CF6?logo=anthropic)](src/agents/)
[![SAST](https://img.shields.io/badge/SAST-Bandit%20%2B%20Semgrep-orange)](.github/workflows/static-analysis.yml)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

---

## Why this project exists

Most QA portfolios show Playwright scripts against a todo app. This one answers a different question:

> *"What does AI-driven quality assurance look like when the domain has safety consequences?"*

SkyGuard simulates the cybersecurity attack surface of an aircraft's digital systems — the EFB tablet a pilot uses for flight planning, the ARINC 429 data bus, the ACARS ground-to-air messaging protocol — and tests it with the same rigour a security team at Airbus Defence or Thales AVS would apply: automated fuzzing, OWASP-aligned attack scenarios, STRIDE threat modelling, and regulatory compliance mapping.

The AI doesn't generate test boilerplate. It **reasons about security**: assigns CVSS scores, chains multi-step attacks, maps findings to DO-326A process gaps, and files GitHub Issues when something regresses.

---

## 90-second demo

```bash
git clone https://github.com/BazanJeremy/skyguard.git && cd skyguard
pip install -r requirements.txt

# Full AI pipeline — fallback mode (no API key needed)
python demo.py --save

# Full test suite — 252 tests, ~8 seconds
pytest tests/ -v
```

With a live API key:
```bash
ANTHROPIC_API_KEY=sk-ant-... python demo.py --save
```

What `demo.py --save` produces in `reports/`:
- `pentest-report.md` — CVSS scores, attack chains, remediation plan
- `stride-threat-model.md` — full STRIDE model from a Gherkin story
- `compliance-matrix.md` — ED-202A gap ratings with corrective actions

---

## What an interviewer sees in 30 seconds

| Signal | Where |
|---|---|
| 252 tests, 7-job CI pipeline | Badge + Actions tab |
| AI agents making real QA decisions | `src/agents/` + `demo.py` output |
| CVSS scoring, STRIDE, ED-202A | `reports/` (pre-generated) |
| 2 real bugs caught by tests, before any manual review | Section below + commit history |
| Honest architectural decisions | `docs/ADR-001` → `ADR-003` |
| One-command environment | `docker compose up` |

---

## Architecture

```
Git commit / PR
      │
      ▼
GitHub Actions — 7 parallel jobs
      │
      ├─ quality-gate      Ruff lint + mypy strict (blocks all downstream)
      ├─ protocol-tests    ARINC 429 + ACARS fuzzing  ──┐
      ├─ security-tests    EFB API W1–W5 attack suite  ─┤─ matrix: Python 3.11 / 3.12
      ├─ agent-tests       AI agent output contracts  ──┘
      │
      ├─ ai-analysis       Pentest Narrator + Compliance Mapper on findings
      │                    Quality gate: critical_count ≤ 2 (W2, W4 are expected)
      │
      ├─ allure-report     Merge all results → GitHub Pages  (main only)
      └─ issue-on-failure  Auto-file GitHub Issue on regression  (main only)

Parallel (PRs + daily):
      static-analysis      Bandit + Semgrep → SARIF → GitHub Security tab

                    ↓ findings fan-out via RabbitMQ ↓

            ┌──────────────────────────────────────┐
            │      AI AGENT LAYER  (Claude API)    │
            ├───────────────┬──────────────────────┤
            │ Pentest       │ Threat     │ Compliance│
            │ Narrator      │ Modeller   │ Mapper   │
            │ CVSS·chains   │ STRIDE     │ ED-202A  │
            │ remediation   │ from       │ DO-326A  │
            │ plan          │ Gherkin    │ gap matrix│
            └───────────────┴──────────────────────┘
                    ↓
      pentest-report.md · stride-threat-model.md · compliance-matrix.md · GitHub Issue
```

---

## Simulated attack surface

### ARINC 429 bus — `src/simulators/arinc429_bus.py`

The avionics data bus standard used on A320, B737, and most commercial aircraft since the 1980s. The simulator encodes and decodes 32-bit words (label / SDI / data / SSM / parity) against the public ARINC 429 Mark 33 specification.

**Four attack injectors:**

| Injector | Attack | Safety relevance |
|---|---|---|
| `OutOfRangeInjector` | Injects altitude / airspeed outside certified range | Instrument misreading |
| `ParityCorruptionInjector` | Flips parity bit to bypass integrity check | Silent data corruption |
| `SSMSpoofingInjector` | Forces NAV labels to `NO_COMPUTED_DATA` | Display blanking / availability |
| `ReplayAttackGenerator` | Retransmits captured frames with shifted timestamps | Stale data injection |

45 protocol tests + property-based fuzzing via Hypothesis.

### ACARS parser — `src/simulators/acars_parser.py`

Aircraft Communications Addressing and Reporting System — the ground-to-air messaging protocol. Tested with **Hypothesis** (50 000+ generated cases per run). Six `ACARSAttackBuilder` methods simulate: buffer overflow, null byte injection, malformed aircraft address, missing ETX terminator, label field injection, and ATC clearance replay.

### EFB API — `src/simulators/efb_api/efb_app.py`

Flask REST API simulating an Electronic Flight Bag — 12 endpoints across authentication, flight plan CRUD, weather (METAR), performance calculation, and role-gated maintenance access.

**Five intentional, documented vulnerabilities:**

| ID | Vulnerability | OWASP | CVSS v3.1 | ED-202A |
|---|---|---|---|---|
| W1 | No rate limiting on `/auth/token` | A07 | 7.5 HIGH | SO-3: enables brute-force pilot impersonation |
| W2 | Hardcoded JWT secret exposed via `/debug` | A02 | **9.8 CRITICAL** | SO-3: token forgery → full system compromise |
| W3 | IDOR — no ownership check on `/flightplans/<id>` | A01 | 8.1 HIGH | SO-3: cross-pilot flight data access |
| W4 | Unauthenticated `/debug` endpoint | A05 | **9.1 CRITICAL** | SO-3: tokens + env vars + JWT secret exposed |
| W5 | Stack traces + server info in error responses | A09 | 5.3 MEDIUM | SO-6: reduces exploitation cost |

Each vulnerability is detected by at least 3 dedicated tests. The debug endpoint (W4) disappears automatically when `FLASK_ENV=production` — demonstrating the fix in one environment variable.

---

## AI agents

All three agents share the same interface contract:
- **With `ANTHROPIC_API_KEY`:** calls `claude-sonnet-4-6`, returns AI-reasoned output
- **Without key:** returns deterministic fallback — all 252 tests pass, CI never blocked

### Agent 1 — Pentest Narrator

**Input:** `list[SecurityFinding]` from the test suite  
**Output:** `PentestReport` — CVSS vectors, attack chains, ordered remediation plan, ED-202A mapping

The agent doesn't summarise findings — it reasons about them:
- Assigns CVSS v3.1 scores with full attack vectors
- Identifies multi-step attack chains (e.g. `W4 unauthenticated debug → enumerate active tokens → W3 IDOR → read any pilot's flight plan`)
- Orders remediation by safety and regulatory impact, not CVSS score alone
- Writes a 2-sentence executive summary for a non-technical CISO

```python
from src.agents.pentest_narrator import PentestNarrator, SecurityFinding, Severity

findings = [SecurityFinding("W4", "Unauthenticated debug endpoint", ...)]
narrator = PentestNarrator()           # auto-detects API key
report   = narrator.analyse(findings)
print(narrator.to_markdown(report))    # full pentest report in Markdown
```

### Agent 2 — Threat Modeller

**Input:** `GherkinStory` (feature title + Given/When/Then scenarios)  
**Output:** `STRIDEModel` — 6 STRIDE categories, attack trees, ED-202A refs, suggested `test_` names

Reads a User Story the way a security architect would in a threat modelling session — extracts actors, assets, trust boundaries — then enumerates threats per STRIDE category with mitigations and test case suggestions in pytest naming convention.

```python
from src.agents.threat_modeller import ThreatModeller, GherkinStory

story    = GherkinStory(feature="EFB flight plan access", as_a="pilot", ...)
modeller = ThreatModeller()
model    = modeller.analyse(story)     # returns STRIDEModel with 6+ threats
```

### Agent 3 — Compliance Mapper

**Input:** `list[SecurityFinding]`  
**Output:** `ComplianceMatrix` — ED-202A SO-1…SO-6 mapping, DO-326A process gaps, gap severity ratings

Gap ratings: `🔴 critical_gap` / `🟠 major_gap` / `🟡 minor_gap` / `🟢 compliant`

> ⚠️ **Scope disclaimer:** This agent demonstrates the *logic and vocabulary* of ED-202A compliance mapping — it is not a formal compliance assessment. Real DO-326A certification requires engagement with an EASA-approved Design Organisation. See [ADR-003](docs/ADR-003-compliance-scope.md) for the full rationale.

---

## Test suite

```
252 passed, 6 skipped   (~8 seconds · no API key needed)
```

| Layer | File(s) | Tests | What's covered |
|---|---|---|---|
| Protocol | `tests/protocol/` | 57 | ARINC 429 encode/decode, BNR, parity, 4 injectors; ACARS parser, 6 attack builders |
| Fuzzing | `tests/fuzzing/` | 27 | Hypothesis: parser never crashes, return type invariant, idempotence, batch consistency |
| Security | `tests/security/test_efb_api.py` | 71 | EFB API contract, RBAC, W1–W5 detection, injection probes, IDOR enumeration |
| Agents | `tests/agents/test_agents.py` | 72 | Output contracts, fallback behaviour, edge cases, Markdown rendering, pipeline integration |
| Live (skipped) | `tests/agents/test_agents.py` | 6 | Claude API call validation — activated with `ANTHROPIC_API_KEY` |

Run a specific layer:
```bash
pytest tests/protocol/ -v -m protocol        # ARINC 429 + ACARS
pytest tests/fuzzing/  -v -m fuzzing         # Hypothesis (generates 50k+ cases)
pytest tests/security/ -v -m security        # EFB attack surface
pytest tests/agents/   -v -m agents          # AI agents (fallback mode)
pytest tests/          -v -m live            # Live API tests (needs ANTHROPIC_API_KEY)
```

---

## Bugs caught by tests — before any manual review

*These are the stories that land in interviews.*

### Bug 1 — `int(None)` → HTTP 500 on flight plan creation

**Discovered by:** `TestInjectionAttacks::test_null_values_in_body`  
**Symptom:** `POST /api/v1/flightplans` with `{"cruise_fl": null}` returned HTTP 500 with a full Python traceback (also triggering W5).  
**Root cause:** `int(body["cruise_fl"])` raised `TypeError: int() argument must be a string, a bytes-like object or a real number, not 'NoneType'` — unhandled at the route level.  
**Fix:** Added `try/except (TypeError, ValueError)` around numeric field parsing → returns 422 with `{"error": "Invalid numeric field: ..."}`.  
**Commit:** fix: handle None and non-numeric cruise_fl/fuel_kg in create_flightplan  

### Bug 2 — `int("three hundred and fifty")` → HTTP 500 on flight plan creation

**Discovered by:** `TestInjectionAttacks::test_type_confusion_on_cruise_fl`  
**Symptom:** String value for `cruise_fl` returned HTTP 500 instead of 400/422.  
**Root cause:** Same unhandled `ValueError` path as Bug 1.  
**Fix:** Same `try/except` block — both bugs fixed together.  
**Interview angle:** *"The type confusion test was designed to probe the boundary between 400 and 500 responses. Finding Bug 1 on nulls was expected. Bug 2 on arbitrary strings exposed that the error was in the conversion, not the validation — a subtle distinction that matters for error handling design."*

---

## CI/CD pipeline

Every push triggers two workflows:

**`security-pipeline.yml` — 7 parallel jobs:**

| Job | Blocks | Purpose |
|---|---|---|
| `quality-gate` | Everything | Ruff lint + mypy strict on `src/agents/` |
| `protocol-tests` (3.11 + 3.12) | `ai-analysis` | ARINC 429 + ACARS (matrix) |
| `security-tests` (3.11 + 3.12) | `ai-analysis` | EFB API W1–W5 attack suite (matrix) |
| `agent-tests` (3.11 + 3.12) | `ai-analysis` | Agent output contracts — fallback (matrix) |
| `ai-analysis` | — | Pentest Narrator + Compliance Mapper; quality gate: `critical_count ≤ 2` |
| `allure-report` | — | Merge artifacts → GitHub Pages (`main` only) |
| `issue-on-failure` | — | Auto-file GitHub Issue with AI analysis summary (`main` only) |

**`static-analysis.yml` — runs on PRs + daily at 03:00 UTC:**
- Bandit (Python SAST, HIGH severity) → SARIF → GitHub Security tab
- Semgrep (`p/python` + `p/security-audit` + `p/owasp-top-ten`) → SARIF

The intentional weaknesses W2 (hardcoded secret) and W4 (debug endpoint) surface in Bandit with `--exit-zero` — documented in [ADR-003](docs/ADR-003-compliance-scope.md) as expected findings, not regressions.

---

## Local environment

**Tests only** (no Docker):
```bash
pip install -r requirements.txt
pytest tests/ -v
python demo.py --save
```

**Full environment** (EFB API + RabbitMQ):
```bash
cp .env.example .env        # set ANTHROPIC_API_KEY if you have one
docker compose up           # EFB API → :5050 · RabbitMQ UI → :15672
```

**Demo the W4 fix:**
```bash
FLASK_ENV=production python demo.py   # /debug endpoint returns 404
```

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Enables live Claude agents. Without it, deterministic fallback runs. |
| `FLASK_ENV` | No | `production` disables `/debug` (W4 remediation demo) |
| `RABBITMQ_HOST` | No | RabbitMQ connection (default: `localhost`) |

---

## Project structure

```
skyguard/
├── .github/
│   ├── workflows/
│   │   ├── security-pipeline.yml     # 7-job CI pipeline
│   │   └── static-analysis.yml       # Bandit + Semgrep → SARIF
│   └── ISSUE_TEMPLATE/
│       └── ai-regression.md          # template for auto-filed issues
├── docs/
│   ├── ADR-001-protocol-simulation.md   # why pure Python simulation
│   ├── ADR-002-ai-agent-design.md       # why Claude API + deterministic fallback
│   └── ADR-003-compliance-scope.md      # honest framing of ED-202A mapping
├── src/
│   ├── simulators/
│   │   ├── arinc429_bus.py           # ARINC 429 encoder/decoder + 4 injectors
│   │   ├── acars_parser.py           # ACARS parser + 6 attack builders
│   │   └── efb_api/efb_app.py        # Flask EFB — 12 endpoints, 5 documented vulns
│   └── agents/
│       ├── pentest_narrator.py       # CVSS + attack chains + remediation plan
│       ├── threat_modeller.py        # STRIDE model from Gherkin story
│       └── compliance_mapper.py      # ED-202A / DO-326A gap matrix
├── tests/
│   ├── protocol/                     # 57 tests — ARINC 429 + ACARS
│   ├── fuzzing/                      # 27 tests — Hypothesis property-based
│   ├── security/                     # 71 tests — EFB attack surface
│   └── agents/                       # 72 tests — AI agent contracts
├── reports/                          # pre-generated AI reports (checked in)
│   ├── pentest-report.md
│   ├── stride-threat-model.md
│   └── compliance-matrix.md
├── infrastructure/
│   └── Dockerfile.efb
├── demo.py                           # end-to-end pipeline demo (30 seconds)
├── docker-compose.yml                # EFB API + RabbitMQ
├── .env.example
├── requirements.txt
└── pytest.ini
```

---

## Regulatory references

| Standard | Role in this project |
|---|---|
| **EASA ED-202A** | Airworthiness Security Process — SO-1…SO-6 objectives used for finding classification |
| **DO-326A** | Airworthiness Security Methods — Section references used in compliance matrix |
| **ARINC 429** | Mark 33 DITS — public spec used for bus simulation frame structure |
| **ARINC 618** | AGC protocol — basis for ACARS message format simulation |
| **OWASP Top 10** | W1–W5 mapped to A01, A02, A05, A07, A09 |
| **CVSS v3.1** | Scoring standard used by Pentest Narrator agent |

> **Disclaimer:** SkyGuard is a QA portfolio project. No certified avionics systems, real aircraft data, or production environments are involved. The compliance mapping is illustrative — see [ADR-003](docs/ADR-003-compliance-scope.md).

---

## Architecture decisions

| ADR | Decision | Why it matters |
|---|---|---|
| [ADR-001](docs/ADR-001-protocol-simulation.md) | Pure Python protocol simulation | Hardware-independent, CI-compatible, Hypothesis-testable |
| [ADR-002](docs/ADR-002-ai-agent-design.md) | Claude API + deterministic fallback | CI never blocked; live mode enhances without depending |
| [ADR-003](docs/ADR-003-compliance-scope.md) | Compliance mapper is illustrative, not certifying | Honest scope framing signals domain awareness |

---

## Stack

| Layer | Tool | Notes |
|---|---|---|
| Language | Python 3.11 / 3.12 | Typed dataclasses throughout |
| API simulator | Flask 3.x | Lightweight, ZAP-compatible |
| Test runner | Pytest 9.x | Allure plugin, rich markers |
| Property testing | Hypothesis | 50 000+ cases per fuzzing session |
| AI agents | Claude `claude-sonnet-4-6` | Structured JSON output, versioned prompts |
| SAST | Bandit + Semgrep | Dual-tool, SARIF output |
| Reporting | Allure → GitHub Pages | Visual, shareable, zero hosting cost |
| Event bus | RabbitMQ 3.13 | Enterprise-grade async broker |
| CI/CD | GitHub Actions | Free tier, parallel matrix, OIDC |
| Containers | Docker Compose | One-command local environment |

All tools are **free and open-source**.

---

*Built by Jérémy Bazan — QA Engineer · ISTQB Foundation v4 · bilingual FR/EN · Lyon, France*  
*Open to QA Lead / SDET / QA Architect roles — Switzerland · Full remote international*

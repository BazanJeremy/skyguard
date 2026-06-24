# SkyGuard EFB — ED-202A / DO-326A Compliance Matrix

> ⚠️ **SIMULATION ONLY — not a formal compliance assessment. Real certification requires engagement with an EASA-approved organisation.**

**Standard:** EASA ED-202A / DO-326A  
**System:** EFB API — SkyGuard simulation  
**Prompt version:** v1.0.0 · **Model:** claude-sonnet-4-6

## Overall Posture

Rule-based assessment (no API key). 2 critical gap(s), 2 major gap(s), 1 minor gap(s) across 5 finding(s). Critical gaps must be resolved before any deployment of the EFB system.

## Gap Summary

| Gap level | Count |
|---|---|
| 🔴 Critical gap | 2 |
| 🟠 Major gap    | 2 |
| 🟡 Minor gap    | 1 |
| 🟢 Compliant    | 0 |

## Compliance Matrix

| Finding | Title | ED-202A Objective | DO-326A Process | Gap |
|---|---|---|---|---|
| `W1` | No rate limiting on auth endpoint | SO-3: Implement security controls | 7.2 — Authentication and access control implementation | 🟠 Major Gap |
| `W2` | Hardcoded weak JWT secret | SO-3: Implement security controls | 7.3 — Cryptographic key management | 🔴 Critical Gap |
| `W3` | IDOR — no ownership check on flight plans | SO-3: Implement security controls | 7.2 — Authorisation and access control | 🟠 Major Gap |
| `W4` | Unauthenticated debug endpoint | SO-3: Implement security controls | 8.1 — Security verification of implemented controls | 🔴 Critical Gap |
| `W5` | Stack traces and server info in responses | SO-6: Manage identified vulnerabilities | 9.1 — Vulnerability management | 🟡 Minor Gap |

## Detailed Findings

### W1 — No rate limiting on auth endpoint

- **ED-202A Objective:** SO-3: Implement security controls
- **ED-202A Section:** Section 5.3 — Security risk assessment
- **DO-326A Process:** 7.2 — Authentication and access control implementation
- **Gap:** 🟠 Major Gap

**Rationale:** No rate limiting on the authentication endpoint violates SO-3. An attacker can perform unlimited credential stuffing, directly threatening pilot identity assurance — a safety-relevant control.

**Corrective action:** Install Flask-Limiter and apply @limiter.limit('5/minute') to POST /api/v1/auth/token. Add progressive delay after 3 failures.

**Verification test:** `test_rate_limit_returns_429_after_5_attempts`

### W2 — Hardcoded weak JWT secret

- **ED-202A Objective:** SO-3: Implement security controls
- **ED-202A Section:** Section 7.1 — Cryptographic controls
- **DO-326A Process:** 7.3 — Cryptographic key management
- **Gap:** 🔴 Critical Gap

**Rationale:** Hardcoded JWT secret 'skyguard-dev-secret-2024' is exposed via the debug endpoint. A compromised secret allows unlimited token forgery, enabling any attacker to impersonate any pilot — critical safety impact.

**Corrective action:** Move JWT_SECRET to environment variable loaded from a secrets vault (e.g. HashiCorp Vault or AWS Secrets Manager). Rotate the secret immediately. Remove /debug from all deployments.

**Verification test:** `test_jwt_secret_not_exposed_in_any_endpoint`

### W3 — IDOR — no ownership check on flight plans

- **ED-202A Objective:** SO-3: Implement security controls
- **ED-202A Section:** Section 6.2 — Security requirements for data integrity
- **DO-326A Process:** 7.2 — Authorisation and access control
- **Gap:** 🟠 Major Gap

**Rationale:** IDOR on GET /flightplans/<id> allows any pilot to read any other pilot's flight plan. Flight plan data includes route, fuel load, and alternates — tampering could lead to a pilot operating with incorrect routing data.

**Corrective action:** Add ownership check: if plan.owner_id != current_user.id and current_user.role != 'dispatcher': return 403. Apply to GET, PUT, and DELETE endpoints.

**Verification test:** `test_pilot_cannot_access_other_pilots_plan`

### W4 — Unauthenticated debug endpoint

- **ED-202A Objective:** SO-3: Implement security controls
- **ED-202A Section:** Section 5.4 — Attack surface reduction
- **DO-326A Process:** 8.1 — Security verification of implemented controls
- **Gap:** 🔴 Critical Gap

**Rationale:** The unauthenticated /debug endpoint exposes active session tokens, all usernames, environment variables, and the JWT secret. This single endpoint negates all other authentication controls — equivalent to leaving the cockpit door unlocked.

**Corrective action:** Remove the /debug endpoint entirely. If debugging is needed in dev, gate it behind FLASK_ENV == 'development' AND require_auth. Add Bandit rule B105 to block hardcoded secrets in CI.

**Verification test:** `test_debug_endpoint_does_not_exist_in_production`

### W5 — Stack traces and server info in responses

- **ED-202A Objective:** SO-6: Manage identified vulnerabilities
- **ED-202A Section:** Section 5.5 — Information disclosure risk
- **DO-326A Process:** 9.1 — Vulnerability management
- **Gap:** 🟡 Minor Gap

**Rationale:** Stack traces, Python version, and hostname in responses aid targeted exploitation but do not directly enable a safety-relevant attack. Classified as minor gap — reduces attack difficulty rather than creating a primary vulnerability.

**Corrective action:** Replace global exception handler to return only {error_id: uuid} without traceback. Remove 'python' and 'system' fields from /version. Remove 'system' field from /health.

**Verification test:** `test_500_response_contains_no_traceback`

---
*Generated by SkyGuard Compliance Mapper · Prompt vv1.0.0 · Model: claude-sonnet-4-6*
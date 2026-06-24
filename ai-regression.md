---
name: "🚨 AI-Detected Security Regression"
about: "Automatically filed by the SkyGuard CI pipeline when a security test fails or a new critical finding is detected."
title: "🚨 CI regression on main — [COMMIT] — failed: [JOBS]"
labels: ["ai-detected", "regression", "ci-failure"]
assignees: []
---

## Regression Summary

> This issue was automatically filed by the **SkyGuard AI Pipeline**.
> Do not close manually — close once the fix is merged to `main`.

### Failure Details

| Field | Value |
|-------|-------|
| **Commit** | <!-- auto-filled by CI --> |
| **Branch** | <!-- auto-filled by CI --> |
| **Failed jobs** | <!-- auto-filled by CI --> |
| **CI run** | <!-- auto-filled by CI --> |

### AI Analysis

<!-- The Pentest Narrator agent will add its executive summary here if ANTHROPIC_API_KEY is set -->

### Compliance Impact

<!-- The Compliance Mapper agent will add ED-202A gap assessment here -->

### Investigation Checklist

- [ ] Reviewed CI run logs
- [ ] Ran `pytest tests/ -v --tb=long` locally — failure reproduced
- [ ] Identified root cause
- [ ] Fix implemented and tests pass
- [ ] PR created referencing this issue (`Fixes #<n>`)
- [ ] Fix merged to `main`
- [ ] Issue closed

### Context

The SkyGuard EFB API contains **five intentional, documented security weaknesses** (W1–W5).
A regression means either:
- A previously-passing test now fails (code change broke something), or
- A new unhandled critical finding appeared beyond the expected W1–W5 baseline.

See [`docs/ADR-003-compliance-scope.md`](../../docs/ADR-003-compliance-scope.md) for the full weakness catalogue.

---
*Filed by SkyGuard AI Pipeline · Model: claude-sonnet-4-6*

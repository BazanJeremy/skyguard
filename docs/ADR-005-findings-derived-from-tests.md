# ADR-005: CI findings are derived from the test results

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Jérémy Bazan

## Context

The pipeline hands a list of security findings to the agents and gates on it: the build fails when the compliance matrix counts more critical gaps than a threshold.

Until now both sides of that comparison were constants. The `security-tests` job wrote `findings.json` from a list of five findings typed into the workflow, whatever the tests had just shown, and the `ai-analysis` job compared the resulting critical count with `CRITICAL_THRESHOLD = 2` — the number of criticals in that same list. The gate could not fail: a weakness could stop being reproducible, or a new one could appear in the simulator, and the pipeline would report the same five findings and pass.

The evidence already existed. Each documented weakness has a test class in `tests/security/test_efb_api.py` (`TestW1NoRateLimiting` … `TestW5InformationDisclosure`, 17 tests) whose tests pass when the weakness is demonstrated.

## Decision

`findings.json` is derived from the JUnit report of the security tests by `src/gate/findings.py`. A documented weakness is a finding only if its `TestW<n>` class ran and all its tests passed.

The step is a gate. It fails when what the tests show differs from the documented baseline:

- a documented weakness has no test behind it — the gate cannot vouch for it;
- a test of a documented weakness fails — it is no longer demonstrated as documented;
- a `TestW<n>` class exists that the baseline does not document.

The baseline (id, title, severity) is declared once, in that module. The critical threshold of `ai-analysis` is computed from it instead of being written in the workflow.

Exit codes: 0 baseline confirmed, 1 deviation, 2 the report is unusable. A crash exits 2, never 1.

The report is parsed with `defusedxml`. It is written by pytest in the same job, so it is not hostile input today; but the first version of this module used the standard `xml` library, and the project's own Semgrep scan flagged it on the pull request (two `use-defused-xml` errors). Measured before the change: a report declaring an entity was expanded and read as a deviation (exit 1). It is now refused as unusable (exit 2). This adds one runtime dependency to a completed project — accepted because it is the remediation of a finding raised by the project's own scanner.

## Options Considered

1. **Derive the findings from the test results** — the gate now depends on evidence and can fail. Costs one small module and its tests. **Chosen.**
2. **Keep the list and rename the step** to what it was, a static reference — honest, but the project's claim is a security quality gate replayed on every commit, and that claim would have nothing behind it.
3. **Derive the findings from a scanner (ZAP, Bandit)** — closer to a real pentest input, but a new dependency on a completed project, and Bandit/Semgrep already run in their own, non-blocking workflow.

## Consequences

- The gate can fail, and says why, naming the weakness.
- Adding a weakness to the simulator now takes three coordinated edits — the simulator, a `TestW<n>` class, the baseline — and the gate fails until all three agree. A test pins that the real suite and the baseline name the same weaknesses.
- The findings carry their evidence (`TestW2HardcodedSecret: 2/2 tests passed`).
- What the gate does **not** do: it does not discover weaknesses. A weakness nobody wrote a test for stays invisible, exactly as before. It verifies that the documented state is the tested state.
- The static-analysis workflow (Bandit, Semgrep) is unchanged and still non-blocking.
- Verified locally on the real suite: 5 of 5 weaknesses demonstrated, 2 criticals observed for 2 expected. The workflow change itself can only be exercised by the CI run of the pull request.

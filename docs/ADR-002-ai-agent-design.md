# ADR-002 — Claude API with deterministic fallback for AI agents

**Status:** Accepted  
**Date:** 2024-01  
**Author:** Jérémy Bazan  

---

## Context

The three AI agents (Pentest Narrator, Threat Modeller, Compliance Mapper) need an LLM backend. The options considered were:

1. **Ollama + local model** (Mistral 7B, Llama 3, CodeLlama)
2. **OpenAI GPT-4o** via API
3. **Anthropic Claude** (`claude-sonnet-4-6`) via API
4. **No LLM** — rule-based only

A second question: what happens in CI when no API key is available?

## Decision

**Use Anthropic Claude (`claude-sonnet-4-6`) as the primary LLM backend, with a mandatory deterministic fallback that activates automatically when `ANTHROPIC_API_KEY` is not set.**

## Rationale

### Why Claude over Ollama

Ollama is attractive for local-only, zero-cost usage. However:

- A 7B parameter model running on CPU produces unreliable structured JSON — critical for agents that must return parseable `PentestReport`, `STRIDEModel`, and `ComplianceMatrix` objects.
- CVSS scoring, STRIDE categorisation, and ED-202A mapping require nuanced domain reasoning that smaller models handle poorly.
- Project context: demonstrating production-grade AI integration (managed API, structured output, versioned prompts) is more credible than local inference for a QA Lead / SDET role.

Ollama remains the recommended local fallback for users who cannot use the API — documented in `.env.example`.

### Why Claude over GPT-4o

Both are viable. Claude was chosen because:
- The project is built with Claude's assistance (consistency of toolchain).
- `claude-sonnet-4-6` has strong structured output reliability on security domain tasks.
- Anthropic's rate limits on the free tier are sufficient for this project's demo needs.

This decision has low switching cost — the agent interface is model-agnostic; changing the model requires one line.

### Why deterministic fallback is non-negotiable

**CI must never be blocked by a missing secret.** The fallback design ensures:

1. All 252 tests pass in CI without `ANTHROPIC_API_KEY`.
2. The 6 live API tests are marked `@pytest.mark.skipif` and excluded gracefully.
3. The `demo.py` script produces meaningful output in fallback mode.
4. A reviewer who forks the repo can run everything immediately.

The fallback is not a degraded mode — it is a first-class execution path with:
- Hardcoded CVSS scores derived from published CVSSv3.1 metrics for each weakness class.
- A complete STRIDE model covering all 6 categories.
- A full ED-202A compliance matrix with rationale.

## Agent design principles

**Versioned prompts.** Every agent carries a `PROMPT_VERSION` constant and logs it in output. This enables regression testing of prompt changes — a technique from production LLM systems.

**Structured JSON output contract.** System prompts specify exact JSON schemas. Agents parse and validate the response before returning typed dataclasses. Invalid JSON from the model raises a catchable exception, not a silent failure.

**Single responsibility.** Each agent does exactly one thing:
- `PentestNarrator` → security findings to pentest report
- `ThreatModeller` → Gherkin story to STRIDE model  
- `ComplianceMapper` → findings to regulatory matrix

This enables independent testing, independent versioning, and independent upgrade.

## Consequences

- Users with an API key get richer, context-aware AI output.
- Users without a key get a complete, deterministic run — zero friction to evaluate the project.
- The cost of a full pipeline run with the API is approximately $0.02–$0.05 (3 agents × ~1500 tokens each).
- Prompt versions must be bumped when system prompts change — tracked in git history.

## References

- Anthropic. *Claude claude-sonnet-4-6 model card.* anthropic.com
- OWASP. *CVSS v3.1 specification.* owasp.org
- Wei, J. et al. (2022). *Chain-of-Thought Prompting Elicits Reasoning in Large Language Models.* NeurIPS.

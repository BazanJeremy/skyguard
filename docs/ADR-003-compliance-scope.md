# ADR-003 — Compliance mapper scope: illustrative, not certifying

**Status:** Accepted  
**Date:** 2024-01  
**Author:** Jérémy Bazan  

---

## Context

The Compliance Mapper agent maps EFB security findings to EASA ED-202A security objectives and DO-326A process sections. This raises an important question: what does "compliance mapping" mean in a solo simulation project, and how should its scope be communicated?

Two failure modes to avoid:

1. **Overclaiming:** presenting the output as a formal compliance assessment, which it is not.
2. **Underclaiming:** not demonstrating the regulatory reasoning at all, missing a key differentiator.

## Decision

**The Compliance Mapper demonstrates the *logic* and *vocabulary* of ED-202A/DO-326A mapping. It is explicitly framed as illustrative — not a substitute for formal certification engagement.**

This framing is:
- Stated in the agent's output (`scope_disclaimer` field in `ComplianceMatrix`)
- Stated in the README (disclaimer box under the Compliance Mapper section)
- Stated in this ADR

## Rationale

### What real DO-326A compliance requires

Real airworthiness security certification under DO-326A / ED-202A involves:
- Engagement with an EASA Design Organisation Approval (DOA) holder
- A formal Security Risk Assessment (SRA) per Section 5
- Independent verification by a DER (Designated Engineering Representative) or EASA-approved body
- Aircraft-level integration and activation (Section 8)
- Continued airworthiness monitoring (Section 9)

None of this is achievable in a solo project.

### What this project *does* demonstrate

The Compliance Mapper demonstrates:
- **Vocabulary fluency:** SO-1 through SO-6, Section 5.3 SRA, DO-326A Section 7.2 — the same terminology a hiring manager at Airbus Defence or Thales AVS would use in a job description.
- **Regulatory reasoning:** mapping a concrete finding (e.g. W3 IDOR) to the correct objective (SO-3: Implement security controls) with a credible rationale.
- **Gap rating logic:** distinguishing critical_gap (violates an SO with safety impact) from minor_gap (reduces exploitation cost without creating a primary vulnerability).
- **AI-assisted regulatory analysis:** a concrete, defensible use case for LLM in a regulated-industry QA context.

### Why honest framing strengthens rather than weakens the project

A candidate who says *"my Compliance Mapper demonstrates the mapping logic of ED-202A — not a formal certification"* shows:
- Domain awareness (they know what real certification requires)
- Professional integrity (they don't overclaim)
- Architectural thinking (they designed the tool with honest scope)

This is more credible to a hiring manager at Safran or Airbus than overclaiming.

## Gap between simulation and reality — documented

| Aspect | This project | Real DO-326A |
|---|---|---|
| Finding identification | Automated test suite | Formal Threat Conditions identification per Section 5.1 |
| Risk assessment | CVSS + ED-202A mapping | Security Risk Assessment with probability/severity matrix |
| Verification | Pytest test suite | Independent verification per Section 8 |
| Scope | Flask EFB API simulation | Full aircraft system including hardware, firmware, ground systems |
| Authority | Project documentation | DOA holder + EASA approval |

## Consequences

- All agent outputs carry the scope disclaimer.
- The README includes a prominent disclaimer box.
- Anyone who probes on regulatory depth will find an author who knows the boundaries.
- The mapping logic is genuine and defensible — this is not hand-waving.

## References

- EASA. *ED-202A: Airworthiness Security Process Specification.* EUROCAE, 2019.
- RTCA. *DO-326A: Airworthiness Security Process Specification.* RTCA, 2014.
- EASA. *AMC 20-42: Airworthiness Security Methods and Considerations.* 2022.
- FAA. *AC 119-1: Airworthiness and Operational Authorization of Aircraft Network Security Program.* 2021.

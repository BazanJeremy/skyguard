# ADR-004 — SO-1…SO-6 is SkyGuard's own objective scale

**Status:** Accepted — supersedes the SO-1…SO-6 vocabulary claim of ADR-003
**Date:** 2026-09-28
**Author:** Jérémy Bazan

---

## Context

ADR-003 presents "SO-1 through SO-6" as ED-202A vocabulary, and the agents
used the labels as "ED-202A Security Objectives". Two problems surfaced when
the claim was checked:

1. **The numbering is not sourced.** ED-202A / DO-326A is a paid standard.
   Public descriptions of it present the airworthiness security process as
   seven steps (plan for security aspects of certification, security scope
   definition, security risk assessment, risk acceptability determination,
   security development, security effectiveness assurance, communication of
   evidence); none of them shows an "SO-1…SO-6" numbering.
2. **The labels did not mean the same thing across agents.** The Compliance
   Mapper defined SO-3 as "Implement security controls", while the Threat
   Modeller's fallback used SO-3 for "Maintain data integrity" (and SO-2, SO-4,
   SO-5, SO-6 for STRIDE-style properties). The same label could not be
   compared from one report to the other.

## Decision

SO-1…SO-6 is **SkyGuard's own simplified objective scale**, aligned on the
ED-202A security process but not taken from the standard's numbering:

| Code | Objective |
|---|---|
| SO-1 | Identify cybersecurity threats and hazards |
| SO-2 | Define security requirements |
| SO-3 | Implement security controls |
| SO-4 | Verify security controls are effective |
| SO-5 | Ensure security is maintained throughout the lifecycle |
| SO-6 | Manage identified vulnerabilities |

- The scale is defined **once**, in `src/agents/objectives.py`, and both the
  Compliance Mapper and the Threat Modeller build their prompts and fallback
  labels from it.
- Prompts, rendered reports and READMEs name it "the SkyGuard scale" and state
  that the SO-n labels are project labels.
- The Threat Modeller's fallback threats are all missing controls whose
  mitigations are controls to implement; they map to SO-3, as the Compliance
  Mapper already maps the same weaknesses (W1, W3, W4).

## Consequences

- ADR-003's scope decision (illustrative, not certifying) stands; only its
  "Vocabulary fluency: SO-1 through SO-6" claim is superseded.
- Field names such as `ed202a_objective` and `ed202a_ref` are kept for API
  stability; their values come from the SkyGuard scale.
- Other references to the standard's internals remain unverified and are not
  covered by this decision: the "DO-326A process sections" list, the
  `ed202a_section` field, and the Pentest Narrator's "T1…T5" categories.

## References

- EE Aero, *DO-326A* glossary entry — https://ee-aero.com/glossary/do-326a/
- PTC, *Basics of DO-326A/ED-202A Airworthiness Security* —
  https://www.ptc.com/en/resources/application-lifecycle-management/ebook/basics-do-326a-ed-202a-airworthiness-security-process-specification

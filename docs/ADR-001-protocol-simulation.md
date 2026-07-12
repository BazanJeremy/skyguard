# ADR-001 — Simulate avionics protocols in pure Python

**Status:** Accepted  
**Date:** 2024-01  
**Author:** Jérémy Bazan  

---

## Context

SkyGuard needs a realistic attack surface to demonstrate cybersecurity QA techniques against avionics systems. The options considered were:

1. Use real avionics hardware (ARINC 429 USB adapters, e.g. AIM GmbH cards)
2. Use a hardware emulation framework (e.g. Qemu with avionics BSP)
3. Simulate protocols in pure Python based on public specifications

## Decision

**Simulate ARINC 429 and ACARS in pure Python**, using only the publicly available protocol specifications (ARINC 429 Mark 33 DITS, ARINC 618 AGC protocol).

## Rationale

**Hardware independence.** This project must run on any developer machine, in CI, and in a reviewer's environment without specialised hardware. A USB ARINC adapter costs €800–€3000 and is not available as a GitHub Actions runner.

**Spec fidelity is sufficient for QA purposes.** The attack surface under test — bit-level frame encoding, parity computation, label catalog validation, and SSM field semantics — is fully specified in public documents. The simulation faithfully implements:
- 32-bit frame structure (label 8b / SDI 2b / data 19b / SSM 2b / parity 1b)
- BNR encoding/decoding with resolution and range per label
- Odd parity computation per word
- Four realistic attack injection patterns derived from published avionics security research

**Testable and reproducible.** Pure Python means Pytest + Hypothesis can instrument the simulator directly — no network stack, no serial port driver, no timing dependency. Property-based testing with 50 000+ generated cases is only feasible against an in-process simulator.

**Honest framing.** The README and this ADR are explicit: this is a simulation, not a certified avionics component. The goal is to demonstrate QA methodology, not to certify flight software.

## Consequences

- No real aircraft data is used or required.
- The attack scenarios are realistic in structure but do not represent vulnerabilities in any production system.
- Reviewers with avionics background will recognise the protocol fidelity; reviewers without will see the testing methodology.
- If a future version of this project were to interface with real hardware, the simulator would serve as a test double (substitutable by the real driver without changing the test suite).

## References

- ARINC 429 Mark 33 Digital Information Transfer System — ARINC Inc.
- ARINC 618: Air/Ground Character-Oriented Protocol Specification
- EASA ED-202A: Airworthiness Security Process Specification (public summary)
- Haass, J. et al. (2016). *Cybersecurity and the Avionics System*. AIAA/IEEE Digital Avionics Systems Conference.

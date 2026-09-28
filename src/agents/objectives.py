"""
SkyGuard objective scale (SO-1..SO-6) — single definition shared by the agents.

This is a simplified scale defined by the SkyGuard project and aligned on the
ED-202A / DO-326A airworthiness security process. The SO-n labels are project
labels, not clause or objective numbers taken from the standard (see ADR-004).
"""

from __future__ import annotations

OBJECTIVES: dict[str, str] = {
    "SO-1": "Identify cybersecurity threats and hazards",
    "SO-2": "Define security requirements",
    "SO-3": "Implement security controls",
    "SO-4": "Verify security controls are effective",
    "SO-5": "Ensure security is maintained throughout the lifecycle",
    "SO-6": "Manage identified vulnerabilities",
}


def objective(code: str) -> str:
    """Return the "SO-n: name" label for a code of the scale."""
    return f"{code}: {OBJECTIVES[code]}"


OBJECTIVE_SCALE_PROMPT = (
    "SkyGuard objective scale (a simplified scale defined by this project and\n"
    "aligned on the ED-202A security process; the SO-n labels are project\n"
    "labels, not numbering taken from the standard):\n"
    + "\n".join(f"  {objective(code)}" for code in OBJECTIVES)
)

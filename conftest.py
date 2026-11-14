"""
SkyGuard — pytest root configuration
=====================================
Adds the project root to sys.path so that all tests can import
`src.simulators.*` without installing the package.

Place this file at the project root (same level as src/ and tests/).
"""

import os
import sys
from collections.abc import MutableMapping
from pathlib import Path

# Insert project root so `from src.simulators.xxx import ...` works everywhere
sys.path.insert(0, str(Path(__file__).parent))

LIVE_OPT_IN = "RUN_LIVE_API_TESTS"


def strip_api_key(environ: MutableMapping[str, str]) -> bool:
    """Remove ``ANTHROPIC_API_KEY`` unless live runs were asked for.

    Returns True when a key was removed. The agents pick the key up from the
    environment when they are constructed, so a key present for another tool
    would turn every contract test into a billed call. Live Claude calls need
    ``RUN_LIVE_API_TESTS=1`` as well as the key.
    """
    if environ.get(LIVE_OPT_IN) == "1":
        return False
    return environ.pop("ANTHROPIC_API_KEY", None) is not None


# Runs when pytest imports this conftest, before any test module is imported:
# the ``live`` skip condition in tests/agents is evaluated at import time.
strip_api_key(os.environ)

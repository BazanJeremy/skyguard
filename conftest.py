"""
SkyGuard — pytest root configuration
=====================================
Adds the project root to sys.path so that all tests can import
`src.simulators.*` without installing the package.

Place this file at the project root (same level as src/ and tests/).
"""

import sys
from pathlib import Path

# Insert project root so `from src.simulators.xxx import ...` works everywhere
sys.path.insert(0, str(Path(__file__).parent))

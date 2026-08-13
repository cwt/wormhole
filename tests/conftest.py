#!/usr/bin/env python3
"""
pytest configuration file for Wormhole tests.
"""

import pytest
import sys
from pathlib import Path

# Add the project root to the path so we can import wormhole modules
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


@pytest.fixture(autouse=True)
def clean_nonce_state():
    """Clear nonce tracking state between tests to prevent cross-test pollution."""
    from wormhole.authentication import _ISSUED_NONCES, _USED_NONCES

    _ISSUED_NONCES.clear()
    _USED_NONCES.clear()
    yield

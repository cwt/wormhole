#!/usr/bin/env python3
"""
pytest configuration file for Wormhole tests.
"""
import sys
from pathlib import Path

# Add the project root to the path so we can import wormhole modules
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

#!/usr/bin/env python3
"""
Unit tests for the version module.
"""
import pytest
from wormhole.version import VERSION


class TestVersion:
    """Test cases for the version module."""

    def test_version_exists(self):
        """Test that VERSION exists and is a string."""
        assert isinstance(VERSION, str)
        assert len(VERSION) > 0

    def test_version_format(self):
        """Test that VERSION follows semantic versioning format."""
        # Simple check that it contains numbers and dots
        assert "." in VERSION
        parts = VERSION.split(".")
        assert len(parts) >= 2
        # Check that major and minor version are numbers
        assert parts[0].isdigit()
        assert parts[1].isdigit()

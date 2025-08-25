#!/usr/bin/env python3
"""
Unit tests for the __main__ module.
"""
import pytest
from unittest.mock import patch
import sys


class TestMain:
    """Test cases for the __main__ module."""

    def test_main_import(self):
        """Test that __main__ module can be imported without errors."""
        # Save original sys.argv
        original_argv = sys.argv[:]

        try:
            # Set a minimal argv to avoid argument parsing issues
            sys.argv = ["wormhole"]

            # Mock wormhole.proxy.main to prevent the server from starting
            with patch("wormhole.proxy.main") as mock_proxy_main:
                # Set up the mock to return a specific value
                mock_proxy_main.return_value = 0

                # This test ensures that the __main__ module can be imported
                # without raising exceptions
                try:
                    from wormhole import __main__

                    imported = True
                except SystemExit:
                    # SystemExit is expected when main() is called
                    imported = True
                except Exception:
                    imported = False

                # Verify that proxy.main was called
                mock_proxy_main.assert_called_once()
        finally:
            # Restore original sys.argv
            sys.argv = original_argv

        assert imported, "__main__ module should be importable"

    def test_main_calls_proxy_main(self):
        """Test that __main__ calls proxy.main."""
        # Save original sys.argv
        original_argv = sys.argv[:]

        try:
            # Set a minimal argv to avoid argument parsing issues
            sys.argv = ["wormhole"]

            # Mock proxy.main to prevent actual execution
            with patch("wormhole.proxy.main") as mock_proxy_main:
                # Set up the mock to return a specific value
                mock_proxy_main.return_value = 0

                # Import __main__ which should call proxy.main()
                try:
                    from wormhole import __main__
                except SystemExit:
                    # SystemExit is expected when main() is called
                    pass

                # Verify that proxy.main was called
                mock_proxy_main.assert_called_once()
        finally:
            # Restore original sys.argv
            sys.argv = original_argv

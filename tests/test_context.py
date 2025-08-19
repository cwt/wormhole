#!/usr/bin/env python3
"""
Unit tests for the RequestContext class.
"""
import pytest
import time
from wormhole.context import RequestContext


class TestRequestContext:
    """Test cases for the RequestContext class."""

    def test_context_creation(self):
        """Test that RequestContext can be created with ident and verbose level."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        context = RequestContext(ident, verbose=2)

        assert context.ident == ident
        assert context.verbose == 2
        assert context.client_ip == "127.0.0.1"
        assert isinstance(context.start_time, float)

    def test_context_default_verbose(self):
        """Test that RequestContext defaults to verbose level 0."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        context = RequestContext(ident)

        assert context.ident == ident
        assert context.verbose == 0

    def test_get_elapsed_time(self):
        """Test that get_elapsed_time returns the correct elapsed time."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        context = RequestContext(ident)

        # Small delay
        time.sleep(0.01)

        elapsed = context.get_elapsed_time()
        assert elapsed > 0.01

    def test_missing_client_ip(self):
        """Test that context handles missing client IP gracefully."""
        ident = {"id": "test123"}  # No client key
        context = RequestContext(ident)

        assert context.client_ip == "unknown"

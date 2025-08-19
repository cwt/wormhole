#!/usr/bin/env python3
"""
Integration tests for the RequestContext usage in the handler module.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import (
    relay_stream,
    process_http_request,
    process_https_tunnel,
)


class TestRequestContextIntegration:
    """Integration tests for RequestContext usage."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_relay_stream_accepts_context(self, context):
        """Test that relay_stream correctly accepts and uses RequestContext."""
        # Create mock reader and writer
        reader = AsyncMock(spec=asyncio.StreamReader)
        writer = Mock(spec=asyncio.StreamWriter)
        writer.is_closing.return_value = False
        writer.close = Mock()
        writer.wait_closed = AsyncMock()

        # Mock the reader to return some data then EOF
        reader.at_eof.side_effect = [False, False, True]
        reader.read.side_effect = [b"test data", b""]

        # This should not raise any exceptions
        result = await relay_stream(reader, writer, context)

        # Verify the writer was called correctly
        writer.write.assert_called_with(b"test data")
        writer.drain.assert_awaited()

        # Verify the result is None (no first line requested)
        assert result is None

    def test_context_has_required_attributes(self, context):
        """Test that RequestContext has all required attributes."""
        # Check that the context has the expected attributes
        assert hasattr(context, "ident")
        assert hasattr(context, "verbose")
        assert hasattr(context, "start_time")
        assert hasattr(context, "client_ip")
        assert hasattr(context, "get_elapsed_time")

        # Check types
        assert isinstance(context.ident, dict)
        assert isinstance(context.verbose, int)
        assert isinstance(context.start_time, float)
        assert isinstance(context.client_ip, str)

        # Check that get_elapsed_time is callable
        assert callable(context.get_elapsed_time)

        # Check that get_elapsed_time returns a float
        assert isinstance(context.get_elapsed_time(), float)

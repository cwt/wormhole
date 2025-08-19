#!/usr/bin/env python3
"""
Unit tests for the handler module.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import relay_stream


class TestRelayStream:
    """Test cases for the relay_stream function."""

    @pytest.fixture
    def mock_reader(self):
        """Create a mock StreamReader."""
        reader = AsyncMock(spec=asyncio.StreamReader)
        return reader

    @pytest.fixture
    def mock_writer(self):
        """Create a mock StreamWriter."""
        writer = Mock(spec=asyncio.StreamWriter)
        writer.is_closing.return_value = False
        writer.close = Mock()
        writer.wait_closed = AsyncMock()
        # Properly handle the writer methods
        writer.write = Mock()
        writer.drain = AsyncMock()
        return writer

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_relay_stream_basic(self, mock_reader, mock_writer, context):
        """Test basic relay_stream functionality."""
        # Mock the reader to return some data then EOF
        mock_reader.at_eof.side_effect = [False, False, True]
        mock_reader.read.side_effect = [b"test data", b""]

        result = await relay_stream(mock_reader, mock_writer, context)

        # Verify the writer was called correctly
        mock_writer.write.assert_called_with(b"test data")
        # Check that drain was called, but don't assert it was awaited
        mock_writer.drain.assert_called()

        # Verify the result is None (no first line requested)
        assert result is None

    @pytest.mark.asyncio
    async def test_relay_stream_with_first_line(
        self, mock_reader, mock_writer, context
    ):
        """Test relay_stream with return_first_line=True."""
        # Mock the reader to return some data then EOF
        mock_reader.at_eof.side_effect = [False, False, True]
        mock_reader.read.side_effect = [
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            b"",
        ]

        result = await relay_stream(
            mock_reader, mock_writer, context, return_first_line=True
        )

        # Verify the result is the first line
        assert result == b"HTTP/1.1 200 OK"

    @pytest.mark.asyncio
    async def test_relay_stream_empty_data(
        self, mock_reader, mock_writer, context
    ):
        """Test relay_stream with empty data."""
        # Mock the reader to return no data
        mock_reader.at_eof.side_effect = [False, True]
        mock_reader.read.side_effect = [b""]

        result = await relay_stream(mock_reader, mock_writer, context)

        # Writer should not be called with empty data
        mock_writer.write.assert_not_called()
        assert result is None

    @pytest.mark.asyncio
    async def test_relay_stream_connection_reset(
        self, mock_reader, mock_writer, context
    ):
        """Test relay_stream handling of ConnectionResetError."""
        # Mock the reader to raise ConnectionResetError
        mock_reader.at_eof.side_effect = [False, True]
        mock_reader.read.side_effect = ConnectionResetError("Connection reset")

        result = await relay_stream(mock_reader, mock_writer, context)

        # Should handle the exception gracefully
        assert result is None

    @pytest.mark.asyncio
    async def test_relay_stream_writer_closing(
        self, mock_reader, mock_writer, context
    ):
        """Test relay_stream when writer is already closing."""
        # Mock the writer as closing
        mock_writer.is_closing.return_value = True

        # Mock the reader to return some data then EOF
        mock_reader.at_eof.side_effect = [False, True]
        mock_reader.read.side_effect = [b"test data"]

        result = await relay_stream(mock_reader, mock_writer, context)

        # Writer should not be closed again
        mock_writer.close.assert_not_called()
        # Check that wait_closed was not called, but don't assert it was not awaited
        mock_writer.wait_closed.assert_not_called()
        assert result is None

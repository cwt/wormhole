#!/usr/bin/env python3
"""
Unit tests for the parse_request function.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import parse_request


class TestParseRequest:
    """Test cases for the parse_request function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.fixture
    def mock_reader(self):
        """Create a mock StreamReader."""
        reader = AsyncMock(spec=asyncio.StreamReader)
        return reader

    @pytest.mark.asyncio
    async def test_parse_request_success(self, mock_reader, context):
        """Test successful parsing of a request."""
        # Mock the reader to return a valid HTTP request
        request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        mock_reader.readuntil = AsyncMock(return_value=request_data)

        result = await parse_request(mock_reader, context)

        # Should return the request line, headers, and empty payload
        request_line, headers, payload = result
        assert request_line == "GET / HTTP/1.1"
        assert headers == ["Host: example.com"]
        assert payload == b""

    @pytest.mark.asyncio
    async def test_parse_request_with_content_length(
        self, mock_reader, context
    ):
        """Test parsing of a request with Content-Length header."""
        # Mock the reader to return a valid HTTP request with payload
        headers_data = b"POST /test HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"
        payload_data = b"test"
        mock_reader.readuntil = AsyncMock(return_value=headers_data)
        mock_reader.readexactly = AsyncMock(return_value=payload_data)

        result = await parse_request(mock_reader, context)

        # Should return the request line, headers, and payload
        request_line, headers, payload = result
        assert request_line == "POST /test HTTP/1.1"
        assert headers == ["Host: example.com", "Content-Length: 4"]
        assert payload == b"test"

    @pytest.mark.asyncio
    async def test_parse_request_timeout(self, mock_reader, context):
        """Test parsing of a request that times out."""
        # Mock the reader to raise a timeout error
        mock_reader.readuntil = AsyncMock(
            side_effect=asyncio.TimeoutError("Timeout")
        )

        result = await parse_request(mock_reader, context)

        # Should return None for all values
        assert result == (None, None, None)

    @pytest.mark.asyncio
    async def test_parse_request_incomplete_read(self, mock_reader, context):
        """Test parsing of a request with incomplete payload."""
        # Mock the reader to return headers but raise an incomplete read error for payload
        headers_data = b"POST /test HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n"
        mock_reader.readuntil = AsyncMock(return_value=headers_data)
        mock_reader.readexactly = AsyncMock(
            side_effect=asyncio.IncompleteReadError(b"test", 10)
        )

        result = await parse_request(mock_reader, context)

        # Should return None for all values
        assert result == (None, None, None)

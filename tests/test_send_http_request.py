#!/usr/bin/env python3
"""
Unit tests for the _send_http_request function.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import _send_http_request


class TestSendHttpRequest:
    """Test cases for the _send_http_request function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_send_http_request_success(self, context):
        """Test successful sending of HTTP request."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80
        method = "GET"
        path = "/"
        version = "HTTP/1.1"
        headers = ["Host: example.com"]
        payload = b""

        # Mock the _create_fastest_connection function
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = Mock(spec=asyncio.StreamWriter)
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        with patch(
            "wormhole.handler._create_fastest_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            reader, writer = await _send_http_request(
                ip_list,
                port,
                method,
                path,
                version,
                headers,
                payload,
                context,
                max_attempts=1,
            )

            # Should return the mock reader and writer
            assert reader == mock_reader
            assert writer == mock_writer

            # Should have written the request
            assert mock_writer.write.call_count >= 1  # At least one write call
            mock_writer.drain.assert_awaited()

    @pytest.mark.asyncio
    async def test_send_http_request_with_payload(self, context):
        """Test sending HTTP request with payload."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80
        method = "POST"
        path = "/test"
        version = "HTTP/1.1"
        headers = ["Host: example.com", "Content-Length: 4"]
        payload = b"test"

        # Mock the _create_fastest_connection function
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = Mock(spec=asyncio.StreamWriter)
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        with patch(
            "wormhole.handler._create_fastest_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            reader, writer = await _send_http_request(
                ip_list,
                port,
                method,
                path,
                version,
                headers,
                payload,
                context,
                max_attempts=1,
            )

            # Should return the mock reader and writer
            assert reader == mock_reader
            assert writer == mock_writer

            # Should have written the request and payload
            assert mock_writer.write.call_count >= 1  # At least one write call
            mock_writer.drain.assert_awaited()

#!/usr/bin/env python3
"""
Additional unit tests for the process_http_request function error conditions.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import process_http_request


class TestProcessHttpRequestErrors:
    """Additional test cases for error conditions in process_http_request function."""

    @pytest.fixture
    def mock_writer(self):
        """Create a mock StreamWriter."""
        writer = Mock(spec=asyncio.StreamWriter)
        writer.is_closing.return_value = False
        writer.close = Mock()
        writer.wait_closed = AsyncMock()
        writer.write = Mock()
        writer.drain = AsyncMock()
        return writer

    @pytest.mark.asyncio
    async def test_process_http_request_ad_domain_blocked(self, mock_writer):
        """Test when the target domain is blocked by ad-blocker."""
        method = "GET"
        uri = "/test"
        version = "HTTP/1.1"
        headers = ["Host: blocked-ads.com"]
        payload = b""

        # Mock _resolve_and_validate_host to raise PermissionError for ad domains
        with patch(
            "wormhole.handler._resolve_and_validate_host",
            new=AsyncMock(side_effect=PermissionError("Blocked ad domain")),
        ):
            await process_http_request(
                mock_writer,
                method,
                uri,
                version,
                headers,
                payload,
                {"id": "test123", "client": "127.0.0.1"},
                False,
                max_attempts=1,
                verbose=1,
            )

            # Should send a 403 Forbidden response
            mock_writer.write.assert_called_with(
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
            )
            mock_writer.drain.assert_awaited()

    @pytest.mark.asyncio
    async def test_process_http_request_bad_request_no_host(self, mock_writer):
        """Test when there's no Host header and URI is not absolute."""
        method = "GET"
        uri = "/test"
        version = "HTTP/1.1"
        headers = []  # No Host header
        payload = b""

        await process_http_request(
            mock_writer,
            method,
            uri,
            version,
            headers,
            payload,
            {"id": "test123", "client": "127.0.0.1"},
            False,
            max_attempts=1,
            verbose=1,
        )

        # Should send a 400 Bad Request response
        mock_writer.write.assert_called_with(
            b"HTTP/1.1 400 Bad Request\r\n\r\n"
        )
        mock_writer.drain.assert_awaited()

    @pytest.mark.asyncio
    async def test_process_http_request_connection_failure(self, mock_writer):
        """Test when connection to target server fails."""
        method = "GET"
        uri = "http://example.com/test"
        version = "HTTP/1.1"
        headers = []  # No Host header, so it tries to parse from URI
        payload = b""

        # Mock _resolve_and_validate_host to return valid IPs
        with patch(
            "wormhole.handler._resolve_and_validate_host",
            new=AsyncMock(return_value=["93.184.216.34"]),
        ):
            # Mock _send_http_request to raise an exception
            with patch(
                "wormhole.handler._send_http_request",
                new=AsyncMock(side_effect=Exception("Connection failed")),
            ):
                await process_http_request(
                    mock_writer,
                    method,
                    uri,
                    version,
                    headers,
                    payload,
                    {"id": "test123", "client": "127.0.0.1"},
                    False,
                    max_attempts=1,
                    verbose=1,
                )

                # Should send a 502 Bad Gateway response
                mock_writer.write.assert_called_with(
                    b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                )
                mock_writer.drain.assert_awaited()

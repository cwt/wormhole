#!/usr/bin/env python3
"""
Additional unit tests for the process_https_tunnel function error conditions.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import process_https_tunnel


class TestProcessHttpsTunnelErrors:
    """Additional test cases for error conditions in process_https_tunnel function."""

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
        writer.write = Mock()
        writer.drain = AsyncMock()
        return writer

    @pytest.mark.asyncio
    async def test_process_https_tunnel_ad_domain_blocked(
        self, mock_reader, mock_writer
    ):
        """Test when the target domain is blocked by ad-blocker."""
        method = "CONNECT"
        uri = "blocked-ads.com:443"

        # Mock _resolve_and_validate_host to raise PermissionError for ad domains
        with patch(
            "wormhole.handler._resolve_and_validate_host",
            new=AsyncMock(side_effect=PermissionError("Blocked ad domain")),
        ):
            await process_https_tunnel(
                mock_reader,
                mock_writer,
                method,
                uri,
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

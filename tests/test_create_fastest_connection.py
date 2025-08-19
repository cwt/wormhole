#!/usr/bin/env python3
"""
Unit tests for the _create_fastest_connection function.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import _create_fastest_connection


class TestCreateFastestConnection:
    """Test cases for the _create_fastest_connection function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_create_fastest_connection_success(self, context):
        """Test successful creation of fastest connection."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80

        # Mock asyncio.open_connection to return mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = Mock(spec=asyncio.StreamWriter)
        mock_writer.get_extra_info.return_value = ("93.184.216.34", 80)

        with patch(
            "wormhole.handler.asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            with patch(
                "wormhole.handler.asyncio.wait_for",
                new=AsyncMock(return_value=(mock_reader, mock_writer)),
            ):
                reader, writer = await _create_fastest_connection(
                    ip_list, port, context, timeout=5, max_attempts=1
                )

                # Should return the mock reader and writer
                assert reader == mock_reader
                assert writer == mock_writer

    @pytest.mark.asyncio
    async def test_create_fastest_connection_failure(self, context):
        """Test failure to create connection."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80

        # Mock asyncio.open_connection to raise an exception
        with patch(
            "wormhole.handler.asyncio.open_connection",
            new=AsyncMock(side_effect=OSError("Connection failed")),
        ):
            with patch(
                "wormhole.handler.asyncio.wait_for",
                new=AsyncMock(side_effect=OSError("Connection failed")),
            ):
                with pytest.raises(OSError) as exc_info:
                    await _create_fastest_connection(
                        ip_list, port, context, timeout=1, max_attempts=1
                    )

                assert "All connection attempts failed" in str(exc_info.value)

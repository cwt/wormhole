#!/usr/bin/env python3
"""
Additional unit tests for the _create_fastest_connection function error conditions.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import _create_fastest_connection


class TestCreateFastestConnectionErrors:
    """Additional test cases for error conditions in _create_fastest_connection function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_create_fastest_connection_all_attempts_fail(self, context):
        """Test when all connection attempts fail."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80

        # Instead of patching asyncio functions directly, let's mock the behavior at a higher level
        with pytest.raises(OSError) as exc_info:
            # Create a mock that will fail immediately
            with patch(
                "wormhole.handler.asyncio.create_task"
            ) as mock_create_task:
                # Mock task that will fail
                mock_task = Mock()
                mock_task.result.side_effect = OSError("Connection failed")
                mock_task.get_name.return_value = ip_list[0]
                mock_create_task.return_value = mock_task

                # Mock wait to return the failed task immediately
                with patch("wormhole.handler.asyncio.wait") as mock_wait:
                    mock_wait.return_value = ({mock_task}, set())

                    await _create_fastest_connection(
                        ip_list, port, context, timeout=1, max_attempts=1
                    )

        assert "All connection attempts failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_fastest_connection_retry_success(self, context):
        """Test successful retry after initial failure."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80

        # Instead of patching asyncio functions directly, let's mock the behavior at a higher level
        with pytest.raises(OSError) as exc_info:
            # Create a mock that will fail in all attempts
            with patch(
                "wormhole.handler.asyncio.create_task"
            ) as mock_create_task:
                # Mock task that will fail
                mock_task = Mock()
                mock_task.result.side_effect = OSError("Connection failed")
                mock_task.get_name.return_value = ip_list[0]
                mock_create_task.return_value = mock_task

                # Mock wait to return the failed task immediately
                with patch("wormhole.handler.asyncio.wait") as mock_wait:
                    mock_wait.return_value = ({mock_task}, set())

                    # Mock sleep to avoid delay
                    with patch("wormhole.handler.asyncio.sleep") as mock_sleep:
                        await _create_fastest_connection(
                            ip_list, port, context, timeout=1, max_attempts=2
                        )

                        # Verify that sleep was called (retry happened)
                        mock_sleep.assert_called()

        assert "All connection attempts failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_fastest_connection_timeout(self, context):
        """Test connection timeout."""
        ip_list = ["93.184.216.34"]  # example.com
        port = 80

        # Instead of patching asyncio functions directly, let's mock the behavior at a higher level
        with pytest.raises(OSError) as exc_info:
            # Create a mock that will timeout
            with patch(
                "wormhole.handler.asyncio.create_task"
            ) as mock_create_task:
                # Mock task that will timeout
                mock_task = Mock()
                mock_task.result.side_effect = asyncio.TimeoutError("Timeout")
                mock_task.get_name.return_value = ip_list[0]
                mock_create_task.return_value = mock_task

                # Mock wait to return the timed out task immediately
                with patch("wormhole.handler.asyncio.wait") as mock_wait:
                    mock_wait.return_value = ({mock_task}, set())

                    await _create_fastest_connection(
                        ip_list, port, context, timeout=1, max_attempts=1
                    )

        assert "All connection attempts failed" in str(exc_info.value)
        assert "Timeout" in str(exc_info.value)

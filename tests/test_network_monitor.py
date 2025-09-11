#!/usr/bin/env python3
"""
Unit tests for the network_monitor module.
"""

import pytest
import asyncio
import socket
from unittest.mock import Mock, patch, MagicMock
from wormhole.network_monitor import (
    is_ipv6_available,
    has_ipv6_connectivity,
    monitor_network_changes,
)


class TestNetworkMonitor:
    """Test cases for the network_monitor module."""

    def test_is_ipv6_available_success(self):
        """Test is_ipv6_available when IPv6 is available."""
        with patch("wormhole.network_monitor.socket.socket") as mock_socket:
            # Mock the socket creation and bind to succeed
            mock_sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = mock_sock_instance
            mock_sock_instance.bind.return_value = None

            result = is_ipv6_available()
            assert result is True

            # Verify the socket was created with the correct parameters
            mock_socket.assert_called_once_with(
                socket.AF_INET6, socket.SOCK_STREAM
            )
            mock_sock_instance.bind.assert_called_once_with(("::1", 0))

    def test_is_ipv6_available_failure(self):
        """Test is_ipv6_available when IPv6 is not available."""
        with patch("wormhole.network_monitor.socket.socket") as mock_socket:
            # Mock the socket creation to raise an exception
            mock_socket.side_effect = OSError("IPv6 not available")

            result = is_ipv6_available()
            assert result is False

    def test_has_ipv6_connectivity_success(self):
        """Test has_ipv6_connectivity when IPv6 connectivity is available."""
        with patch("wormhole.network_monitor.socket.socket") as mock_socket:
            # Mock the socket creation and connect to succeed
            mock_sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = mock_sock_instance
            mock_sock_instance.settimeout.return_value = None
            mock_sock_instance.connect.return_value = None

            result = has_ipv6_connectivity()
            assert result is True

            # Verify the socket was created with the correct parameters
            mock_socket.assert_called_once_with(
                socket.AF_INET6, socket.SOCK_STREAM
            )
            mock_sock_instance.settimeout.assert_called_once_with(3)
            mock_sock_instance.connect.assert_called_once_with(
                ("2001:4860:4860::8888", 53)
            )

    def test_has_ipv6_connectivity_failure(self):
        """Test has_ipv6_connectivity when IPv6 connectivity is not available."""
        with patch("wormhole.network_monitor.socket.socket") as mock_socket:
            # Mock the socket creation to raise an exception on connect
            mock_sock_instance = Mock()
            mock_socket.return_value.__enter__.return_value = mock_sock_instance
            mock_sock_instance.settimeout.return_value = None
            mock_sock_instance.connect.side_effect = OSError(
                "No IPv6 connectivity"
            )

            result = has_ipv6_connectivity()
            assert result is False

    @pytest.mark.asyncio
    async def test_monitor_network_changes_ipv6_becomes_available(self):
        """Test monitor_network_changes when IPv6 becomes available."""
        with (
            patch(
                "wormhole.network_monitor.is_ipv6_available"
            ) as mock_ipv6_available,
            patch(
                "wormhole.network_monitor.has_ipv6_connectivity"
            ) as mock_ipv6_connectivity,
            patch("wormhole.network_monitor.logger") as mock_logger,
            patch("wormhole.network_monitor.asyncio.sleep") as mock_sleep,
        ):
            # Initial state: IPv6 not available, then becomes available
            mock_ipv6_available.side_effect = [
                False,
                True,
                True,
            ]  # Initial check False, then True in loop, then True again
            mock_ipv6_connectivity.return_value = False

            # First sleep should work, second should raise CancelledError to break the loop
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            # Call the function
            result = await monitor_network_changes(
                check_interval=1, verbose=1, host="127.0.0.1"
            )

            # Should return True when IPv6 becomes available
            assert result is True

    @pytest.mark.asyncio
    async def test_monitor_network_changes_cancelled(self):
        """Test monitor_network_changes when cancelled."""
        with (
            patch(
                "wormhole.network_monitor.is_ipv6_available"
            ) as mock_ipv6_available,
            patch(
                "wormhole.network_monitor.has_ipv6_connectivity"
            ) as mock_ipv6_connectivity,
            patch("wormhole.network_monitor.logger") as mock_logger,
            patch("wormhole.network_monitor.asyncio.sleep") as mock_sleep,
        ):
            # Initial state: IPv6 not available
            mock_ipv6_available.return_value = False
            mock_ipv6_connectivity.return_value = False

            # Make sleep raise a CancelledError immediately
            mock_sleep.side_effect = asyncio.CancelledError()

            # Call the function
            result = await monitor_network_changes(
                check_interval=1, verbose=1, host="127.0.0.1"
            )

            # Should return False when cancelled
            assert result is False

    @pytest.mark.asyncio
    async def test_monitor_network_changes_exception(self):
        """Test monitor_network_changes when an exception occurs."""
        with (
            patch(
                "wormhole.network_monitor.is_ipv6_available"
            ) as mock_ipv6_available,
            patch(
                "wormhole.network_monitor.has_ipv6_connectivity"
            ) as mock_ipv6_connectivity,
            patch("wormhole.network_monitor.logger") as mock_logger,
            patch("wormhole.network_monitor.asyncio.sleep") as mock_sleep,
        ):
            # Initial state: IPv6 not available
            mock_ipv6_available.return_value = False
            mock_ipv6_connectivity.return_value = False

            # Make sleep raise a generic exception immediately, then raise CancelledError to break loop
            mock_sleep.side_effect = [
                Exception("Test error"),
                asyncio.CancelledError(),
            ]

            # Call the function
            result = await monitor_network_changes(
                check_interval=1, verbose=1, host="127.0.0.1"
            )

            # Should return False when an exception occurs
            assert result is False
            mock_logger.error.assert_called()  # Should have logged the error

    @pytest.mark.asyncio
    async def test_monitor_network_changes_no_change(self):
        """Test monitor_network_changes when no network changes occur."""
        with (
            patch(
                "wormhole.network_monitor.is_ipv6_available"
            ) as mock_ipv6_available,
            patch(
                "wormhole.network_monitor.has_ipv6_connectivity"
            ) as mock_ipv6_connectivity,
            patch("wormhole.network_monitor.logger") as mock_logger,
            patch("wormhole.network_monitor.asyncio.sleep") as mock_sleep,
        ):
            # Initial state: IPv6 not available, and stays that way
            mock_ipv6_available.return_value = False
            mock_ipv6_connectivity.return_value = False

            # Make sleep raise an exception to break the loop immediately
            mock_sleep.side_effect = asyncio.CancelledError()

            # Call the function
            result = await monitor_network_changes(
                check_interval=1, verbose=1, host="127.0.0.1"
            )

            # Should return False when no changes occur
            assert result is False

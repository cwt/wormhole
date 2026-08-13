#!/usr/bin/env python3
"""
Unit tests for the server module.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from wormhole.server import handle_connection, start_wormhole_server, MAX_TASKS


class TestHandleConnection:
    """Test cases for the handle_connection function."""

    @pytest.mark.asyncio
    async def test_handle_connection_empty_request(self):
        """Test handle_connection with an empty request."""
        # Mock the reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        # Mock parse_request to return None values (empty request)
        with patch(
            "wormhole.server.parse_request", return_value=(None, None, None)
        ):
            with patch("wormhole.server.get_ident") as mock_get_ident:
                mock_get_ident.return_value = {
                    "id": "123456",
                    "client": "192.168.1.1",
                }

                # This should complete without raising an exception
                await handle_connection(
                    mock_reader,
                    mock_writer,
                    auth_file_path=None,
                    verbose=0,
                    allow_private=False,
                )

    @pytest.mark.asyncio
    async def test_handle_connection_malformed_request(self):
        """Test handle_connection with a malformed request line."""
        # Mock the reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        # Mock parse_request to return a malformed request line
        with patch(
            "wormhole.server.parse_request", return_value=("GET", [], b"")
        ):
            with patch("wormhole.server.get_ident") as mock_get_ident:
                mock_get_ident.return_value = {
                    "id": "123456",
                    "client": "192.168.1.1",
                }

                # This should complete without raising an exception
                await handle_connection(
                    mock_reader,
                    mock_writer,
                    auth_file_path=None,
                    verbose=0,
                    allow_private=False,
                )

    @pytest.mark.asyncio
    async def test_handle_connection_http_request(self):
        """Test handle_connection with a valid HTTP request."""
        # Mock the reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        # Mock parse_request to return a valid HTTP request
        with patch(
            "wormhole.server.parse_request",
            return_value=("GET / HTTP/1.1", [], b""),
        ):
            with patch("wormhole.server.get_ident") as mock_get_ident:
                mock_get_ident.return_value = {
                    "id": "123456",
                    "client": "192.168.1.1",
                }
                with patch(
                    "wormhole.server.process_http_request"
                ) as mock_process_http:
                    # This should complete without raising an exception
                    await handle_connection(
                        mock_reader,
                        mock_writer,
                        auth_file_path=None,
                        verbose=0,
                        allow_private=False,
                    )

                    # Verify process_http_request was called
                    mock_process_http.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_connection_https_tunnel(self):
        """Test handle_connection with a CONNECT request."""
        # Mock the reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        # Mock parse_request to return a CONNECT request
        with patch(
            "wormhole.server.parse_request",
            return_value=("CONNECT example.com:443 HTTP/1.1", [], b""),
        ):
            with patch("wormhole.server.get_ident") as mock_get_ident:
                mock_get_ident.return_value = {
                    "id": "123456",
                    "client": "192.168.1.1",
                }
                with patch(
                    "wormhole.server.process_https_tunnel"
                ) as mock_process_https:
                    # This should complete without raising an exception
                    await handle_connection(
                        mock_reader,
                        mock_writer,
                        auth_file_path=None,
                        verbose=0,
                        allow_private=False,
                    )

                    # Verify process_https_tunnel was called
                    mock_process_https.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_connection_with_auth(self):
        """Test handle_connection with authentication."""
        # Mock the reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        # Mock parse_request to return a valid HTTP request
        with patch(
            "wormhole.server.parse_request",
            return_value=("GET / HTTP/1.1", [], b""),
        ):
            with patch("wormhole.server.get_ident") as mock_get_ident:
                mock_get_ident.return_value = {
                    "id": "123456",
                    "client": "192.168.1.1",
                }
                with patch(
                    "wormhole.server.verify_credentials",
                    return_value={"id": "user123", "client": "192.168.1.1"},
                ) as mock_verify:
                    with patch(
                        "wormhole.server.process_http_request"
                    ) as mock_process_http:
                        # This should complete without raising an exception
                        await handle_connection(
                            mock_reader,
                            mock_writer,
                            auth_file_path="/path/to/auth",
                            verbose=0,
                            allow_private=False,
                        )

                        # Verify verify_credentials was called
                        mock_verify.assert_called_once()

                        # Verify process_http_request was called
                        mock_process_http.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_connection_auth_failed(self):
        """Test handle_connection with failed authentication."""
        # Mock the reader and writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()

        # Mock parse_request to return a valid HTTP request
        with patch(
            "wormhole.server.parse_request",
            return_value=("GET / HTTP/1.1", [], b""),
        ):
            with patch("wormhole.server.get_ident") as mock_get_ident:
                mock_get_ident.return_value = {
                    "id": "123456",
                    "client": "192.168.1.1",
                }
                with patch(
                    "wormhole.server.verify_credentials", return_value=None
                ) as mock_verify:
                    # This should complete without raising an exception
                    await handle_connection(
                        mock_reader,
                        mock_writer,
                        auth_file_path="/path/to/auth",
                        verbose=0,
                        allow_private=False,
                    )

                    # Verify verify_credentials was called
                    mock_verify.assert_called_once()


class TestStartWormholeServer:
    """Test cases for the start_wormhole_server function."""

    @pytest.mark.asyncio
    async def test_start_wormhole_server_ipv4(self):
        """Test starting the server with IPv4."""
        with patch("asyncio.start_server") as mock_start_server:
            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server

            with patch("wormhole.server.logger") as mock_logger:
                server = await start_wormhole_server(
                    host="127.0.0.1",
                    port=8080,
                    auth_file_path=None,
                    verbose=0,
                    allow_private=False,
                )

                # Verify start_server was called with correct parameters
                mock_start_server.assert_called_once()
                assert server == mock_server

    @pytest.mark.asyncio
    async def test_start_wormhole_server_ipv6(self):
        """Test starting the server with IPv6."""
        with patch("asyncio.start_server") as mock_start_server:
            mock_server = AsyncMock()
            mock_start_server.return_value = mock_server

            with patch("wormhole.server.logger") as mock_logger:
                server = await start_wormhole_server(
                    host="::1",
                    port=8080,
                    auth_file_path=None,
                    verbose=0,
                    allow_private=False,
                )

                # Verify start_server was called with correct parameters
                mock_start_server.assert_called_once()
                assert server == mock_server

    @pytest.mark.asyncio
    async def test_start_wormhole_server_bind_failure(self):
        """Test starting the server when binding fails."""
        with patch(
            "asyncio.start_server",
            side_effect=OSError("Address already in use"),
        ):
            with patch("wormhole.server.logger") as mock_logger:
                with pytest.raises(OSError):
                    await start_wormhole_server(
                        host="127.0.0.1",
                        port=8080,
                        auth_file_path=None,
                        verbose=0,
                        allow_private=False,
                    )

    @pytest.mark.asyncio
    async def test_handle_connection_rejects_over_max_tasks(self):
        """Test that connections are rejected when MAX_TASKS is exceeded."""
        import wormhole.server as server_module

        mock_reader = AsyncMock()
        mock_writer = Mock()
        mock_writer.is_closing.return_value = False
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.get_extra_info.return_value = ("127.0.0.1", 12345)
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()

        # Save original values
        orig_max = server_module.MAX_TASKS
        orig_current = server_module.CURRENT_TASKS

        try:
            # Set MAX_TASKS=1 and CURRENT_TASKS=1 so next connection exceeds limit
            server_module.MAX_TASKS = 1
            server_module.CURRENT_TASKS = 1

            await handle_connection(
                mock_reader, mock_writer, auth_file_path=None, verbose=0
            )

            # Should have written 503 response
            call_args = mock_writer.write.call_args[0][0]
            assert b"503 Service Unavailable" in call_args
        finally:
            server_module.MAX_TASKS = orig_max
            server_module.CURRENT_TASKS = orig_current

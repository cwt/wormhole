#!/usr/bin/env python3
"""
Unit tests for the handler module.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import (
    relay_stream,
    _create_fastest_connection,
    process_https_tunnel,
    _send_http_request,
    process_http_request,
    parse_request,
)


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


class TestCreateFastestConnection:
    """Test cases for the _create_fastest_connection function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_create_fastest_connection_success(self, context):
        """Test successful connection creation."""
        ip_list = ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
        port = 80

        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)
        mock_writer.get_extra_info.return_value = ("93.184.216.34", 80)

        with patch(
            "asyncio.open_connection", return_value=(mock_reader, mock_writer)
        ):
            reader, writer = await _create_fastest_connection(
                ip_list, port, context
            )

            # Should return the mock reader and writer
            assert reader == mock_reader
            assert writer == mock_writer

    @pytest.mark.asyncio
    async def test_create_fastest_connection_all_fail(self, context):
        """Test handling when all connection attempts fail."""
        ip_list = ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
        port = 80

        with patch(
            "asyncio.open_connection", side_effect=OSError("Connection failed")
        ):
            with pytest.raises(OSError, match="All connection attempts failed"):
                await _create_fastest_connection(
                    ip_list, port, context, max_attempts=1
                )


class TestProcessHttpsTunnel:
    """Test cases for the process_https_tunnel function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_process_https_tunnel_success(self):
        """Test successful HTTPS tunnel establishment."""
        # Create mock readers and writers
        client_reader = AsyncMock(spec=asyncio.StreamReader)
        client_writer = AsyncMock(spec=asyncio.StreamWriter)
        server_reader = AsyncMock(spec=asyncio.StreamReader)
        server_writer = AsyncMock(spec=asyncio.StreamWriter)

        ident = {"id": "test123", "client": "127.0.0.1"}
        method = "CONNECT"
        uri = "example.com:443"
        allow_private = False

        with (
            patch(
                "wormhole.handler._resolve_and_validate_host"
            ) as mock_resolve,
            patch(
                "wormhole.handler._create_fastest_connection"
            ) as mock_connect,
            patch("wormhole.handler.relay_stream") as mock_relay,
        ):

            # Mock the resolution and connection functions
            mock_resolve.return_value = ["93.184.216.34"]
            mock_connect.return_value = (server_reader, server_writer)

            # Mock relay_stream to avoid actual data relay
            mock_relay.return_value = None

            await process_https_tunnel(
                client_reader, client_writer, method, uri, ident, allow_private
            )

            # Verify that the client was sent the success response
            client_writer.write.assert_called_with(
                b"HTTP/1.1 200 Connection established\r\n\r\n"
            )
            client_writer.drain.assert_called()

    @pytest.mark.asyncio
    async def test_process_https_tunnel_blocked_domain(self):
        """Test HTTPS tunnel with blocked domain."""
        # Create mock readers and writers
        client_reader = AsyncMock(spec=asyncio.StreamReader)
        client_writer = AsyncMock(spec=asyncio.StreamWriter)

        ident = {"id": "test123", "client": "127.0.0.1"}
        method = "CONNECT"
        uri = "ads.example.com:443"
        allow_private = False

        with patch(
            "wormhole.handler._resolve_and_validate_host",
            side_effect=PermissionError("Blocked ad domain"),
        ):
            await process_https_tunnel(
                client_reader, client_writer, method, uri, ident, allow_private
            )

            # Verify that the client was sent the forbidden response
            client_writer.write.assert_called_with(
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
            )
            client_writer.drain.assert_called()


class TestSendHttpRequest:
    """Test cases for the _send_http_request function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_send_http_request_success(self, context):
        """Test successful HTTP request sending."""
        ip_list = ["93.184.216.34"]
        port = 80
        method = "GET"
        path = "/"
        version = "HTTP/1.1"
        headers = ["Host: example.com"]
        payload = b""

        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        with patch(
            "wormhole.handler._create_fastest_connection",
            return_value=(mock_reader, mock_writer),
        ):
            reader, writer = await _send_http_request(
                ip_list, port, method, path, version, headers, payload, context
            )

            # Should return the mock reader and writer
            assert reader == mock_reader
            assert writer == mock_writer

            # Verify that the request was written to the writer
            mock_writer.write.assert_called()
            mock_writer.drain.assert_called()


class TestProcessHttpRequest:
    """Test cases for the process_http_request function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_process_http_request_success(self):
        """Test successful HTTP request processing."""
        client_writer = AsyncMock(spec=asyncio.StreamWriter)
        method = "GET"
        uri = "/"
        version = "HTTP/1.1"
        headers = ["Host: example.com"]
        payload = b""
        ident = {"id": "test123", "client": "127.0.0.1"}
        allow_private = False

        # Create mock reader and writer
        server_reader = AsyncMock(spec=asyncio.StreamReader)
        server_writer = AsyncMock(spec=asyncio.StreamWriter)

        with (
            patch(
                "wormhole.handler._resolve_and_validate_host"
            ) as mock_resolve,
            patch("wormhole.handler._send_http_request") as mock_send,
            patch("wormhole.handler.relay_stream") as mock_relay,
        ):

            # Mock the resolution and sending functions
            mock_resolve.return_value = ["93.184.216.34"]
            mock_send.return_value = (server_reader, server_writer)

            # Mock relay_stream to return a status line
            mock_relay.return_value = b"HTTP/1.1 200 OK"

            await process_http_request(
                client_writer,
                method,
                uri,
                version,
                headers,
                payload,
                ident,
                allow_private,
            )

            # Verify that relay_stream was called
            mock_relay.assert_called()

    @pytest.mark.asyncio
    async def test_process_http_request_blocked_domain(self):
        """Test HTTP request processing with blocked domain."""
        client_writer = AsyncMock(spec=asyncio.StreamWriter)
        method = "GET"
        uri = "/"
        version = "HTTP/1.1"
        headers = ["Host: ads.example.com"]
        payload = b""
        ident = {"id": "test123", "client": "127.0.0.1"}
        allow_private = False

        with patch(
            "wormhole.handler._resolve_and_validate_host",
            side_effect=PermissionError("Blocked ad domain"),
        ):
            await process_http_request(
                client_writer,
                method,
                uri,
                version,
                headers,
                payload,
                ident,
                allow_private,
            )

            # Verify that the client was sent the forbidden response
            client_writer.write.assert_called_with(
                b"HTTP/1.1 403 Forbidden\r\n\r\n"
            )
            client_writer.drain.assert_called()


class TestParseRequest:
    """Test cases for the parse_request function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_parse_request_success(self, context):
        """Test successful request parsing."""
        client_reader = AsyncMock(spec=asyncio.StreamReader)

        # Mock the reader to return a complete request
        request_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        client_reader.readuntil.return_value = request_data
        client_reader.readexactly.return_value = b""

        request_line, headers, payload = await parse_request(
            client_reader, context
        )

        # Verify the parsed components
        assert request_line == "GET / HTTP/1.1"
        assert headers == ["Host: example.com"]
        assert payload == b""

    @pytest.mark.asyncio
    async def test_parse_request_with_payload(self, context):
        """Test request parsing with payload."""
        client_reader = AsyncMock(spec=asyncio.StreamReader)

        # Mock the reader to return a request with payload
        headers_data = (
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n"
        )
        payload_data = b"hello"

        client_reader.readuntil.return_value = headers_data
        client_reader.readexactly.return_value = payload_data

        request_line, headers, payload = await parse_request(
            client_reader, context
        )

        # Verify the parsed components
        assert request_line == "POST / HTTP/1.1"
        assert headers == ["Host: example.com", "Content-Length: 5"]
        assert payload == b"hello"

    @pytest.mark.asyncio
    async def test_parse_request_timeout(self, context):
        """Test request parsing with timeout."""
        client_reader = AsyncMock(spec=asyncio.StreamReader)

        # Mock the reader to raise a timeout
        client_reader.readuntil.side_effect = asyncio.TimeoutError("Timeout")

        request_line, headers, payload = await parse_request(
            client_reader, context
        )

        # Should return None for all components
        assert request_line is None
        assert headers is None
        assert payload is None

    @pytest.mark.asyncio
    async def test_parse_request_incomplete_read(self, context):
        """Test request parsing with incomplete read."""
        client_reader = AsyncMock(spec=asyncio.StreamReader)

        # Mock the reader to raise an incomplete read
        client_reader.readuntil.side_effect = asyncio.IncompleteReadError(
            b"GET /", 10
        )

        request_line, headers, payload = await parse_request(
            client_reader, context
        )

        # Should return None for all components
        assert request_line is None
        assert headers is None
        assert payload is None

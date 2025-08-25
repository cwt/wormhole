#!/usr/bin/env python3
"""
Unit tests for the authentication module.
"""
import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from wormhole.authentication import (
    get_ident,
    _load_auth_file,
    _parse_digest_header,
    send_auth_required_response,
    verify_credentials,
    REALM,
    HASH_ALGORITHM,
)


class TestAuthentication:
    """Test cases for the authentication module."""

    def test_get_ident_without_user(self):
        """Test get_ident without a user."""
        # Create mock reader and writer
        mock_reader = Mock(spec=asyncio.StreamReader)
        mock_writer = Mock(spec=asyncio.StreamWriter)

        # Mock the peername
        mock_writer.get_extra_info.return_value = ("192.168.1.100", 12345)

        ident = get_ident(mock_reader, mock_writer)

        # Verify the ident dictionary
        assert "id" in ident
        assert ident["client"] == "192.168.1.100"
        assert len(ident["id"]) == 6  # Should be 6 hex characters

    def test_get_ident_with_user(self):
        """Test get_ident with a user."""
        # Create mock reader and writer
        mock_reader = Mock(spec=asyncio.StreamReader)
        mock_writer = Mock(spec=asyncio.StreamWriter)

        # Mock the peername
        mock_writer.get_extra_info.return_value = ("192.168.1.100", 12345)

        ident = get_ident(mock_reader, mock_writer, "testuser")

        # Verify the ident dictionary
        assert "id" in ident
        assert ident["client"] == "testuser@192.168.1.100"
        assert len(ident["id"]) == 6  # Should be 6 hex characters

    def test_get_ident_unknown_peer(self):
        """Test get_ident when peername is unknown."""
        # Create mock reader and writer
        mock_reader = Mock(spec=asyncio.StreamReader)
        mock_writer = Mock(spec=asyncio.StreamWriter)

        # Mock the peername as None
        mock_writer.get_extra_info.return_value = None

        ident = get_ident(mock_reader, mock_writer)

        # Verify the ident dictionary
        assert "id" in ident
        assert ident["client"] == "unknown"
        assert len(ident["id"]) == 6  # Should be 6 hex characters

    def test_parse_digest_header_quoted_values(self):
        """Test _parse_digest_header with quoted values."""
        header = (
            'Digest username="testuser", realm="Wormhole Proxy", nonce="abc123"'
        )
        result = _parse_digest_header(header)

        assert result["username"] == "testuser"
        assert result["realm"] == "Wormhole Proxy"
        assert result["nonce"] == "abc123"

    def test_parse_digest_header_unquoted_values(self):
        """Test _parse_digest_header with unquoted values."""
        header = "Digest username=testuser, realm=WormholeProxy, nonce=abc123"
        result = _parse_digest_header(header)

        assert result["username"] == "testuser"
        assert result["realm"] == "WormholeProxy"
        assert result["nonce"] == "abc123"

    def test_parse_digest_header_mixed_values(self):
        """Test _parse_digest_header with mixed quoted and unquoted values."""
        header = 'Digest username="testuser", realm=WormholeProxy, nonce=abc123'
        result = _parse_digest_header(header)

        assert result["username"] == "testuser"
        assert result["realm"] == "WormholeProxy"
        assert result["nonce"] == "abc123"

    def test_load_auth_file_exists(self):
        """Test _load_auth_file when the file exists."""
        content = "user1:realm1:hash1\nuser2:realm2:hash2\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            users = _load_auth_file(tmp_path)
            assert users is not None
            assert len(users) == 2
            assert users["user1"]["realm"] == "realm1"
            assert users["user1"]["hash"] == "hash1"
            assert users["user2"]["realm"] == "realm2"
            assert users["user2"]["hash"] == "hash2"
        finally:
            os.remove(tmp_path)

    def test_load_auth_file_not_exists(self):
        """Test _load_auth_file when the file doesn't exist."""
        users = _load_auth_file(Path("/nonexistent/file"))
        assert users is None

    def test_load_auth_file_malformed_line(self):
        """Test _load_auth_file when there are malformed lines."""
        content = "user1:realm1:hash1\nmalformed_line\nuser2:realm2:hash2\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            users = _load_auth_file(tmp_path)
            assert users is not None
            assert len(users) == 2  # Should ignore malformed line
            assert "user1" in users
            assert "user2" in users
        finally:
            os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_send_auth_required_response(self):
        """Test send_auth_required_response."""
        # Create a mock writer
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        # Call the function
        await send_auth_required_response(mock_writer)

        # Verify the writer was called correctly
        mock_writer.write.assert_called_once()
        mock_writer.drain.assert_awaited_once()

        # Verify the response contains the expected elements
        call_args = mock_writer.write.call_args[0][0]
        assert b"HTTP/1.1 407 Proxy Authentication Required" in call_args
        assert b"Proxy-Authenticate: Digest" in call_args
        assert b'realm="' + REALM.encode() + b'"' in call_args
        assert b'qop="auth"' in call_args
        assert b"algorithm=SHA-256" in call_args
        assert b"nonce=" in call_args
        assert b"opaque=" in call_args

    @pytest.mark.asyncio
    async def test_verify_credentials_no_auth_header(self):
        """Test verify_credentials when no auth header is provided."""
        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        # Create a temporary auth file
        content = "testuser:testrealm:testhash\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            # Call verify_credentials without an auth header
            result = await verify_credentials(
                mock_reader,
                mock_writer,
                "CONNECT",
                [],  # Empty headers
                tmp_path,
            )

            # Should return None
            assert result is None

            # Should have sent an auth required response
            mock_writer.write.assert_called_once()
            mock_writer.drain.assert_awaited_once()
        finally:
            os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_verify_credentials_no_auth_file(self):
        """Test verify_credentials when no auth file exists."""
        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        # Call verify_credentials with a nonexistent auth file
        result = await verify_credentials(
            mock_reader,
            mock_writer,
            "CONNECT",
            [],  # Empty headers
            "/nonexistent/authfile",
        )

        # Should return None
        assert result is None

        # Should have sent an auth required response
        mock_writer.write.assert_called_once()
        mock_writer.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_verify_credentials_invalid_auth_header(self):
        """Test verify_credentials with an invalid auth header."""
        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        # Create a temporary auth file
        content = "testuser:testrealm:testhash\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            # Call verify_credentials with an invalid auth header
            result = await verify_credentials(
                mock_reader,
                mock_writer,
                "CONNECT",
                ["Proxy-Authorization: InvalidHeader"],  # Invalid header
                tmp_path,
            )

            # Should return None
            assert result is None

            # Should have sent an auth required response
            mock_writer.write.assert_called_once()
            mock_writer.drain.assert_awaited_once()
        finally:
            os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_verify_credentials_user_not_found(self):
        """Test verify_credentials when user is not found."""
        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        # Create a temporary auth file with a different user
        content = "otheruser:testrealm:testhash\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            # Create a valid-looking auth header for a different user
            auth_header = (
                "Proxy-Authorization: Digest "
                'username="testuser", '
                f'realm="{REALM}", '
                'nonce="abc123", '
                'uri="/", '
                'response="invalidresponse"'
            )

            # Call verify_credentials
            result = await verify_credentials(
                mock_reader, mock_writer, "CONNECT", [auth_header], tmp_path
            )

            # Should return None
            assert result is None

            # Should have sent an auth required response
            mock_writer.write.assert_called_once()
            mock_writer.drain.assert_awaited_once()
        finally:
            os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_verify_credentials_valid_credentials(self):
        """Test verify_credentials with valid credentials."""
        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)
        mock_writer.get_extra_info.return_value = ("192.168.1.100", 12345)

        # Create test credentials
        username = "testuser"
        password = "testpassword"

        # Calculate the expected HA1 hash
        ha1_data = f"{username}:{REALM}:{password}".encode("utf-8")
        ha1 = HASH_ALGORITHM(ha1_data).hexdigest()

        # Create a temporary auth file with the user
        content = f"{username}:{REALM}:{ha1}\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            # Create a valid auth header
            auth_header = (
                "Proxy-Authorization: Digest "
                f'username="{username}", '
                f'realm="{REALM}", '
                'nonce="abc123", '
                'uri="/", '
                'qop="auth", '
                'nc="00000001", '
                'cnonce="xyz789", '
                'response="calculatedresponse"'
            )

            # Calculate the expected response
            ha2_data = f"CONNECT:/".encode("utf-8")
            ha2 = HASH_ALGORITHM(ha2_data).hexdigest()
            response_data = f"{ha1}:abc123:00000001:xyz789:auth:{ha2}".encode(
                "utf-8"
            )
            expected_response = HASH_ALGORITHM(response_data).hexdigest()

            # Update the auth header with the correct response
            auth_header = auth_header.replace(
                'response="calculatedresponse"',
                f'response="{expected_response}"',
            )

            # Patch secrets.compare_digest to return True for our test
            with patch(
                "wormhole.authentication.secrets.compare_digest",
                return_value=True,
            ):
                # Call verify_credentials
                result = await verify_credentials(
                    mock_reader, mock_writer, "CONNECT", [auth_header], tmp_path
                )

                # Should return an ident dictionary
                assert result is not None
                assert "id" in result
                assert result["client"] == f"{username}@192.168.1.100"

                # Writer should not have been called to send auth required response
                mock_writer.write.assert_not_called()
                mock_writer.drain.assert_not_called()
        finally:
            os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_verify_credentials_invalid_credentials(self):
        """Test verify_credentials with invalid credentials."""
        # Create mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = AsyncMock(spec=asyncio.StreamWriter)

        # Create a temporary auth file with a user
        content = "testuser:testrealm:testhash\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            # Create an auth header with incorrect credentials
            auth_header = (
                "Proxy-Authorization: Digest "
                'username="testuser", '
                f'realm="{REALM}", '
                'nonce="abc123", '
                'uri="/", '
                'response="invalidresponse"'
            )

            # Call verify_credentials
            result = await verify_credentials(
                mock_reader, mock_writer, "CONNECT", [auth_header], tmp_path
            )

            # Should return None
            assert result is None

            # Should have sent an auth required response
            mock_writer.write.assert_called_once()
            mock_writer.drain.assert_awaited_once()
        finally:
            os.remove(tmp_path)

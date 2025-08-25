#!/usr/bin/env python3
"""
Unit tests for the auth_manager module.
"""
import pytest
import tempfile
import os
import stat
from pathlib import Path
from unittest.mock import patch, MagicMock
from wormhole.auth_manager import (
    _get_password_confirm,
    _secure_create_file,
    _read_auth_file,
    _write_auth_file,
    add_user,
    modify_user,
    delete_user,
    REALM,
    HASH_ALGORITHM,
)


class TestAuthManager:
    """Test cases for the auth_manager module."""

    def test_get_password_confirm_match(self):
        """Test _get_password_confirm when passwords match."""
        with patch(
            "getpass.getpass", side_effect=["password123", "password123"]
        ):
            result = _get_password_confirm()
            assert result == "password123"

    def test_get_password_confirm_mismatch(self):
        """Test _get_password_confirm when passwords don't match."""
        with patch("getpass.getpass", side_effect=["password123", "different"]):
            with patch("sys.stderr") as mock_stderr:
                result = _get_password_confirm()
                assert result is None
                # Just check that write was called, not the exact message
                mock_stderr.write.assert_called()

    def test_get_password_confirm_cancelled(self):
        """Test _get_password_confirm when operation is cancelled."""
        with patch("getpass.getpass", side_effect=KeyboardInterrupt):
            with patch("sys.stderr") as mock_stderr:
                result = _get_password_confirm()
                assert result is None
                # Just check that write was called, not the exact message
                mock_stderr.write.assert_called()

    def test_secure_create_file_posix(self):
        """Test _secure_create_file on POSIX systems."""
        with patch("sys.platform", "linux"):
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = Path(tmp.name)

            try:
                # Remove the file so we can create it
                os.remove(tmp_path)

                result = _secure_create_file(tmp_path)
                assert result is True
                assert tmp_path.exists()

                # Check permissions (0600)
                if hasattr(os, "stat") and hasattr(os, "chmod"):
                    stat_info = os.stat(tmp_path)
                    assert stat.S_IMODE(stat_info.st_mode) == 0o600
            finally:
                if tmp_path.exists():
                    os.remove(tmp_path)

    def test_secure_create_file_posix_error(self):
        """Test _secure_create_file on POSIX systems when there's an error."""
        with patch("sys.platform", "linux"):
            with patch("os.open", side_effect=OSError("Permission denied")):
                with patch("sys.stderr") as mock_stderr:
                    result = _secure_create_file(Path("/nonexistent/path"))
                    assert result is False
                    mock_stderr.write.assert_called()

    def test_read_auth_file_exists(self):
        """Test _read_auth_file when the file exists."""
        content = "user1:realm1:hash1\nuser2:realm2:hash2\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            users = _read_auth_file(tmp_path)
            assert len(users) == 2
            assert users["user1"]["realm"] == "realm1"
            assert users["user1"]["hash"] == "hash1"
            assert users["user2"]["realm"] == "realm2"
            assert users["user2"]["hash"] == "hash2"
        finally:
            os.remove(tmp_path)

    def test_read_auth_file_not_exists(self):
        """Test _read_auth_file when the file doesn't exist."""
        users = _read_auth_file(Path("/nonexistent/file"))
        assert users == {}

    def test_read_auth_file_malformed_line(self):
        """Test _read_auth_file when there are malformed lines."""
        content = "user1:realm1:hash1\nmalformed_line\nuser2:realm2:hash2\n"
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            users = _read_auth_file(tmp_path)
            assert len(users) == 2  # Should ignore malformed line
            assert "user1" in users
            assert "user2" in users
        finally:
            os.remove(tmp_path)

    def test_write_auth_file(self):
        """Test _write_auth_file."""
        users = {
            "user1": {"realm": "realm1", "hash": "hash1"},
            "user2": {"realm": "realm2", "hash": "hash2"},
        }

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            _write_auth_file(tmp_path, users)

            # Read back and verify
            with open(tmp_path, "r") as f:
                content = f.read()

            lines = content.strip().split("\n")
            assert len(lines) == 2
            assert "user1:realm1:hash1" in lines
            assert "user2:realm2:hash2" in lines
        finally:
            os.remove(tmp_path)

    def test_add_user_new_file(self):
        """Test add_user when creating a new auth file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            with patch(
                "getpass.getpass", side_effect=["password123", "password123"]
            ):
                with patch("sys.stderr") as mock_stderr:
                    result = add_user(auth_file, "testuser")
                    assert result == 0

            # Verify the file was created
            assert os.path.exists(auth_file)

            # Verify the user was added
            users = _read_auth_file(Path(auth_file))
            assert "testuser" in users
            assert users["testuser"]["realm"] == REALM

            # Verify the hash is correct
            ha1_data = f"testuser:{REALM}:password123".encode("utf-8")
            expected_hash = HASH_ALGORITHM(ha1_data).hexdigest()
            assert users["testuser"]["hash"] == expected_hash

    def test_add_user_existing_file(self):
        """Test add_user when adding to an existing auth file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            # Create an existing file with one user
            existing_users = {
                "existinguser": {"realm": REALM, "hash": "existinghash"}
            }
            _write_auth_file(Path(auth_file), existing_users)

            # Add a new user
            with patch(
                "getpass.getpass", side_effect=["password123", "password123"]
            ):
                result = add_user(auth_file, "newuser")
                assert result == 0

            # Verify both users exist
            users = _read_auth_file(Path(auth_file))
            assert len(users) == 2
            assert "existinguser" in users
            assert "newuser" in users

    def test_add_user_already_exists(self):
        """Test add_user when the user already exists."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            # Create an existing file with the user
            existing_users = {
                "testuser": {"realm": REALM, "hash": "existinghash"}
            }
            _write_auth_file(Path(auth_file), existing_users)

            with patch("sys.stderr") as mock_stderr:
                result = add_user(auth_file, "testuser")
                assert result == 1
                mock_stderr.write.assert_called()

    def test_add_user_password_mismatch(self):
        """Test add_user when passwords don't match."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            with patch(
                "getpass.getpass", side_effect=["password123", "different"]
            ):
                with patch("sys.stderr") as mock_stderr:
                    result = add_user(auth_file, "testuser")
                    assert result == 1

    def test_modify_user_success(self):
        """Test modify_user when successful."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            # Create an existing file with a user
            existing_users = {"testuser": {"realm": REALM, "hash": "oldhash"}}
            _write_auth_file(Path(auth_file), existing_users)

            # Modify the user's password
            with patch(
                "getpass.getpass",
                side_effect=["newpassword123", "newpassword123"],
            ):
                result = modify_user(auth_file, "testuser")
                assert result == 0

            # Verify the hash was updated
            users = _read_auth_file(Path(auth_file))
            assert "testuser" in users
            assert users["testuser"]["realm"] == REALM

            # Verify the new hash is correct
            ha1_data = f"testuser:{REALM}:newpassword123".encode("utf-8")
            expected_hash = HASH_ALGORITHM(ha1_data).hexdigest()
            assert users["testuser"]["hash"] == expected_hash

    def test_modify_user_not_found(self):
        """Test modify_user when the user is not found."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            # Create an existing file without the user
            existing_users = {
                "otheruser": {"realm": REALM, "hash": "existinghash"}
            }
            _write_auth_file(Path(auth_file), existing_users)

            with patch("sys.stderr") as mock_stderr:
                result = modify_user(auth_file, "testuser")
                assert result == 1
                mock_stderr.write.assert_called()

    def test_modify_user_file_not_found(self):
        """Test modify_user when the auth file is not found."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "nonexistent.txt")

            with patch("sys.stderr") as mock_stderr:
                result = modify_user(auth_file, "testuser")
                assert result == 1
                mock_stderr.write.assert_called()

    def test_delete_user_success(self):
        """Test delete_user when successful."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            # Create an existing file with users
            existing_users = {
                "user1": {"realm": REALM, "hash": "hash1"},
                "user2": {"realm": REALM, "hash": "hash2"},
            }
            _write_auth_file(Path(auth_file), existing_users)

            # Delete one user
            result = delete_user(auth_file, "user1")
            assert result == 0

            # Verify only the other user remains
            users = _read_auth_file(Path(auth_file))
            assert len(users) == 1
            assert "user2" in users
            assert "user1" not in users

    def test_delete_user_not_found(self):
        """Test delete_user when the user is not found."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "auth.txt")

            # Create an existing file without the user
            existing_users = {
                "otheruser": {"realm": REALM, "hash": "existinghash"}
            }
            _write_auth_file(Path(auth_file), existing_users)

            with patch("sys.stderr") as mock_stderr:
                result = delete_user(auth_file, "testuser")
                assert result == 1
                mock_stderr.write.assert_called()

    def test_delete_user_file_not_found(self):
        """Test delete_user when the auth file is not found."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            auth_file = os.path.join(tmp_dir, "nonexistent.txt")

            with patch("sys.stderr") as mock_stderr:
                result = delete_user(auth_file, "testuser")
                assert result == 1
                mock_stderr.write.assert_called()

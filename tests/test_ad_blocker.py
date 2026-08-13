#!/usr/bin/env python3
"""
Unit tests for the ad_blocker module.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch, mock_open
from wormhole.ad_blocker import (
    BLOCKLIST_URLS,
    DOMAIN_REGEX,
    _fetch_list,
    _parse_domains_from_content,
    _filter_redundant_domains,
    update_database,
)


class TestAdBlocker:
    """Test cases for the ad_blocker module."""

    def test_domain_regex(self):
        """Test the DOMAIN_REGEX pattern."""
        # Test hosts file format
        match = DOMAIN_REGEX.match("0.0.0.0 example.com")
        assert match
        assert match.group(1) == "example.com"

        # Test Adblock Plus format
        match = DOMAIN_REGEX.match("||example.com^")
        assert match
        assert match.group(2) == "example.com"

        # Test simple domain
        match = DOMAIN_REGEX.match("example.com")
        assert match is None  # This should not match the regex

    def test_parse_domains_from_content(self):
        """Test parsing domains from content."""
        content = """
# Comment line
0.0.0.0 ads.example.com
||tracker.com^
! Another comment
subdomain.example.org
        """

        domains = _parse_domains_from_content(content)
        assert "ads.example.com" in domains
        assert "tracker.com" in domains
        assert "subdomain.example.org" in domains
        # Comments and empty lines should be ignored
        assert len(domains) == 3

    def test_parse_domains_from_content_with_comments(self):
        """Test parsing domains while ignoring comments and empty lines."""
        content = """
# This is a comment
! This is also a comment

0.0.0.0 example.com
||tracker.com^

example.org
        """

        domains = _parse_domains_from_content(content)
        assert len(domains) == 3
        assert "example.com" in domains
        assert "tracker.com" in domains
        assert "example.org" in domains

    def test_filter_redundant_domains(self):
        """Test filtering redundant subdomains."""
        domains = {
            "ads.google.com",
            "google.com",
            "api.facebook.com",
            "facebook.com",
            "example.com",
        }

        filtered = _filter_redundant_domains(domains)
        # Should keep parent domains and remove subdomains
        assert "google.com" in filtered
        assert "facebook.com" in filtered
        assert "example.com" in filtered
        # Subdomains should be removed
        assert "ads.google.com" not in filtered
        assert "api.facebook.com" not in filtered
        assert len(filtered) == 3

    def test_filter_redundant_domains_no_redundancy(self):
        """Test filtering when there are no redundant domains."""
        domains = {"google.com", "facebook.com", "example.com"}

        filtered = _filter_redundant_domains(domains)
        # All domains should be kept
        assert "google.com" in filtered
        assert "facebook.com" in filtered
        assert "example.com" in filtered
        assert len(filtered) == 3

    @pytest.mark.asyncio
    async def test_fetch_list_success(self):
        """Test successful fetching of a blocklist."""

        # Create a proper async context manager mock
        class MockResponse:
            status = 200

            async def text(self):
                return "0.0.0.0 example.com"

        # Create an async context manager that returns our mock response
        class MockContextManager:
            async def __aenter__(self):
                return MockResponse()

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_session = AsyncMock()
        mock_session.get = Mock(return_value=MockContextManager())

        # Patch asyncio.sleep to avoid delays during testing
        with patch("wormhole.ad_blocker.asyncio.sleep"):
            result = await _fetch_list(
                mock_session, "http://example.com/list.txt"
            )
        assert "example.com" in result

    @pytest.mark.asyncio
    async def test_fetch_list_failure(self):
        """Test failed fetching of a blocklist."""

        # Create a proper async context manager mock for a failed response
        class MockResponse:
            status = 404

            async def text(self):
                return ""

        # Create an async context manager that returns our mock response
        class MockContextManager:
            async def __aenter__(self):
                return MockResponse()

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        mock_session = AsyncMock()
        mock_session.get = Mock(return_value=MockContextManager())

        # Patch asyncio.sleep to avoid delays during testing
        with patch("wormhole.ad_blocker.asyncio.sleep"):
            result = await _fetch_list(
                mock_session, "http://example.com/list.txt"
            )
        assert result == ""

    @pytest.mark.asyncio
    async def test_update_database(self):
        """Test updating the ad-block database."""

        # Mock the aiohttp session and responses
        class MockResponse:
            status = 200

            async def text(self):
                return "0.0.0.0 example.com"

        # Create an async context manager that returns our mock response
        class MockContextManager:
            async def __aenter__(self):
                return MockResponse()

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        # Mock the ClientSession context manager
        class MockClientSession:
            async def __aenter__(self):
                mock_session = AsyncMock()
                mock_session.get = Mock(return_value=MockContextManager())
                return mock_session

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        # Mock aiosqlite
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock()
        mock_db.executemany = AsyncMock()
        mock_db.commit = AsyncMock()

        # Mock BLOCKLIST_URLS to avoid fetching real URLs
        mock_urls = ["http://example.com/list1.txt"]

        # Patch asyncio.sleep to avoid delays during testing
        with patch("wormhole.ad_blocker.asyncio.sleep"):
            with patch("wormhole.ad_blocker.BLOCKLIST_URLS", mock_urls):
                with patch("aiohttp.ClientSession", MockClientSession):
                    with patch(
                        "aiosqlite.connect",
                        return_value=AsyncMock(
                            __aenter__=AsyncMock(return_value=mock_db)
                        ),
                    ):
                        with patch(
                            "builtins.open", mock_open(read_data="allowed.com")
                        ):
                            await update_database(
                                "/tmp/test.db", "/tmp/allowlist.txt"
                            )

        # Verify that the database operations were called
        mock_db.execute.assert_called()
        mock_db.executemany.assert_called()
        mock_db.commit.assert_called()

    @pytest.mark.asyncio
    async def test_update_database_blocklist_file_not_found(self):
        """Test updating the ad-block database with a non-existent blocklist file."""
        import tempfile
        import os

        # Create a temporary allowlist file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as allow_temp:
            allow_temp.write("allowed.com\nwhitelisted.org\n")
            allowlist_path = allow_temp.name

        # Create a non-existent blocklist path
        nonexistent_blocklist = "/path/that/does/not/exist/blocklist.txt"

        try:
            # Mock the aiohttp session and responses
            class MockResponse:
                status = 200

                async def text(self):
                    return "0.0.0.0 example.com\n0.0.0.0 tracker.com\n"

            # Create an async context manager that returns our mock response
            class MockContextManager:
                async def __aenter__(self):
                    return MockResponse()

                async def __aexit__(self, exc_type, exc_val, exc_tb):
                    pass

            # Mock the ClientSession context manager
            class MockClientSession:
                async def __aenter__(self):
                    mock_session = AsyncMock()
                    mock_session.get = Mock(return_value=MockContextManager())
                    return mock_session

                async def __aexit__(self, exc_type, exc_val, exc_tb):
                    pass

            # Mock the database
            mock_db = AsyncMock()
            mock_db.execute = AsyncMock()
            mock_db.executemany = AsyncMock()
            mock_db.commit = AsyncMock()

            # Mock BLOCKLIST_URLS to avoid fetching real URLs
            mock_urls = ["http://example.com/list1.txt"]

            # Patch logger to verify warning message
            with patch("wormhole.ad_blocker.logger") as mock_logger:
                # Patch asyncio.sleep to avoid delays during testing
                with patch("wormhole.ad_blocker.asyncio.sleep"):
                    with patch("wormhole.ad_blocker.BLOCKLIST_URLS", mock_urls):
                        with patch("aiohttp.ClientSession", MockClientSession):
                            with patch(
                                "aiosqlite.connect",
                                return_value=AsyncMock(
                                    __aenter__=AsyncMock(return_value=mock_db)
                                ),
                            ):
                                # Call update_database with non-existent blocklist file
                                await update_database(
                                    "/tmp/test.db",
                                    allowlist_path,
                                    nonexistent_blocklist,
                                )

                # Verify that warning was logged for missing blocklist file
                mock_logger.warning.assert_called()
                # Check that the specific warning message was called
                warning_calls = [
                    call for call in mock_logger.warning.call_args_list
                ]
                warning_messages = [str(call[0][0]) for call in warning_calls]
                warning_found = any(
                    "Custom blocklist file not found" in msg
                    for msg in warning_messages
                )
                assert (
                    warning_found
                ), "Expected warning for missing blocklist file was not logged"
        finally:
            # Clean up temporary file
            os.unlink(allowlist_path)

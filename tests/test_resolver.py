#!/usr/bin/env python3
"""
Unit tests for the resolver module.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch, mock_open
from wormhole.resolver import Resolver, resolver
import aiodns


class TestResolver:
    """Test cases for the Resolver class."""

    def test_resolver_singleton(self):
        """Test that Resolver is a singleton."""
        resolver1 = Resolver.get_instance()
        resolver2 = Resolver.get_instance()

        # Should be the same instance
        assert resolver1 is resolver2

    def test_resolver_initialize(self):
        """Test initializing the resolver."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=2)

        # Should set the verbose level
        assert resolver_instance.verbose == 2

    def test_get_hosts_path_windows(self):
        """Test getting hosts path on Windows."""
        with patch("sys.platform", "win32"):
            with patch("os.environ", {"SYSTEMROOT": "/windows"}):
                resolver_instance = Resolver.get_instance()
                hosts_path = resolver_instance._get_hosts_path()

                # Should return Windows hosts path
                assert str(hosts_path) == "/windows/System32/drivers/etc/hosts"

    @patch("platform.system", return_value="Linux")
    def test_get_hosts_path_unix(self, mock_system):
        """Test getting hosts path on Unix-like systems."""
        resolver_instance = Resolver.get_instance()
        hosts_path = resolver_instance._get_hosts_path()

        # Should return Unix hosts path
        assert str(hosts_path) == "/etc/hosts"

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="127.0.0.1 localhost\n192.168.1.1 example.com # comment\n",
    )
    @patch("pathlib.Path.exists", return_value=True)
    def test_load_hosts_file_success(self, mock_exists, mock_file):
        """Test successfully loading hosts file."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=1)
        resolver_instance._load_hosts_file()

        # Should have loaded the hosts
        assert resolver_instance.hosts_cache["localhost"] == "127.0.0.1"
        assert resolver_instance.hosts_cache["example.com"] == "192.168.1.1"

    @patch("pathlib.Path.exists", return_value=False)
    def test_load_hosts_file_not_found(self, mock_exists):
        """Test loading hosts file when it doesn't exist."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=1)
        # Save original cache
        original_cache = resolver_instance.hosts_cache.copy()
        resolver_instance._load_hosts_file()

        # Should not modify the existing cache
        assert resolver_instance.hosts_cache == original_cache

    @patch("builtins.open", side_effect=Exception("Permission denied"))
    @patch("pathlib.Path.exists", return_value=True)
    def test_load_hosts_file_error(self, mock_exists, mock_file):
        """Test loading hosts file when there's an error."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=1)
        # Save original cache
        original_cache = resolver_instance.hosts_cache.copy()
        resolver_instance._load_hosts_file()

        # Should not modify the existing cache
        assert resolver_instance.hosts_cache == original_cache

    @pytest.mark.asyncio
    async def test_resolve_from_hosts_cache(self):
        """Test resolving hostname from hosts cache."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=1)
        resolver_instance.hosts_cache["example.com"] = "192.168.1.1"

        result = await resolver_instance.resolve("example.com")

        # Should return the cached IP
        assert result == ["192.168.1.1"]

    @pytest.mark.asyncio
    async def test_resolve_dns_success(self):
        """Test resolving hostname via DNS."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=1)
        resolver_instance.hosts_cache = {}  # Clear cache

        # Mock DNS resolver
        mock_dns_resolver = AsyncMock()
        mock_dns_resolver.query = AsyncMock(
            side_effect=[
                [Mock(host="93.184.216.34")],  # A record
                [
                    Mock(host="2606:2800:220:1:248:1893:25c8:1946")
                ],  # AAAA record
            ]
        )

        with patch.object(resolver_instance, "resolver", mock_dns_resolver):
            result = await resolver_instance.resolve("example.com")

            # Should return both IPv4 and IPv6 addresses
            assert "93.184.216.34" in result
            assert "2606:2800:220:1:248:1893:25c8:1946" in result

    @pytest.mark.asyncio
    async def test_resolve_dns_failure(self):
        """Test resolving hostname when DNS fails."""
        resolver_instance = Resolver.get_instance()
        resolver_instance.initialize(verbose=1)
        resolver_instance.hosts_cache = {}  # Clear cache

        # Mock DNS resolver to raise an error
        mock_dns_resolver = AsyncMock()
        mock_dns_resolver.query = AsyncMock(
            side_effect=aiodns.error.DNSError(
                aiodns.error.ARES_ENOTFOUND, "Domain not found"
            )
        )

        with patch.object(resolver_instance, "resolver", mock_dns_resolver):
            with pytest.raises(OSError) as exc_info:
                await resolver_instance.resolve("nonexistent.example.com")

            assert "Failed to resolve host" in str(exc_info.value)

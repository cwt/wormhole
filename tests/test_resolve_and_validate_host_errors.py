#!/usr/bin/env python3
"""
Additional unit tests for the _resolve_and_validate_host function error conditions.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import _resolve_and_validate_host
from wormhole.safeguards import is_ad_domain, is_private_ip
from wormhole.resolver import resolver


class TestResolveAndValidateHostErrors:
    """Additional test cases for error conditions in _resolve_and_validate_host function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_dns_cache_hit(self, context):
        """Test DNS cache hit scenario."""
        host = "example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the DNS cache to have a hit
            with patch(
                "wormhole.handler.DNS_CACHE",
                {"example.com": (["93.184.216.34"], 0)},
            ):
                # Mock time to make the cache valid
                with patch("wormhole.handler.time.time", return_value=100):
                    result = await _resolve_and_validate_host(
                        host, context, False
                    )

                    # Should return the cached IP list
                    assert result == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_dns_cache_expired(self, context):
        """Test DNS cache expired scenario."""
        host = "example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the DNS cache to have an expired entry
            with patch(
                "wormhole.handler.DNS_CACHE",
                {"example.com": (["93.184.216.34"], 0)},
            ):
                # Mock time to make the cache expired
                with patch("wormhole.handler.time.time", return_value=100000):
                    # Mock the resolver to return a valid IP
                    with patch("wormhole.handler.resolver") as mock_resolver:
                        mock_resolver.resolve = AsyncMock(
                            return_value=["93.184.216.34"]
                        )

                        # Mock is_private_ip to return False for the IP
                        with patch(
                            "wormhole.handler.is_private_ip", return_value=False
                        ):
                            # Mock has_public_ipv6 to return False
                            with patch(
                                "wormhole.handler.has_public_ipv6",
                                return_value=False,
                            ):
                                result = await _resolve_and_validate_host(
                                    host, context, False
                                )

                                # Should return the IP list from resolver
                                assert result == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_resolution_failure(self, context):
        """Test DNS resolution failure."""
        host = "nonexistent.example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the resolver to raise an OSError
            with patch("wormhole.handler.resolver") as mock_resolver:
                mock_resolver.resolve = AsyncMock(
                    side_effect=OSError("DNS resolution failed")
                )

                with pytest.raises(OSError) as exc_info:
                    await _resolve_and_validate_host(host, context, False)

                assert "Failed to resolve host" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_only_private_ips(self, context):
        """Test when host resolves to only private IPs."""
        host = "private.example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the resolver to return a private IP
            with patch("wormhole.handler.resolver") as mock_resolver:
                mock_resolver.resolve = AsyncMock(return_value=["192.168.1.1"])

                # Mock is_private_ip to return True for the IP
                with patch("wormhole.handler.is_private_ip", return_value=True):
                    with pytest.raises(PermissionError) as exc_info:
                        await _resolve_and_validate_host(host, context, False)

                    assert "Blocked access to 'private.example.com'" in str(
                        exc_info.value
                    )

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_allow_private(self, context):
        """Test when private IPs are allowed."""
        host = "private.example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the resolver to return a private IP
            with patch("wormhole.handler.resolver") as mock_resolver:
                mock_resolver.resolve = AsyncMock(return_value=["192.168.1.1"])

                # Mock is_private_ip to return True for the IP
                with patch("wormhole.handler.is_private_ip", return_value=True):
                    result = await _resolve_and_validate_host(
                        host, context, True
                    )  # allow_private=True

                    # Should return the private IP since it's allowed
                    assert result == ["192.168.1.1"]

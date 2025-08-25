#!/usr/bin/env python3
"""
Unit tests for DNS TTL-based caching functionality.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import _resolve_and_validate_host, DNS_CACHE
from wormhole.safeguards import is_ad_domain, is_private_ip
from wormhole.resolver import resolver


class TestDnsTtlCaching:
    """Test cases for DNS TTL-based caching functionality."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_dns_cache_uses_ttl_expiration(self, context):
        """Test that DNS cache respects TTL for expiration."""
        host = "example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the DNS cache to have a valid entry with TTL-based expiration
            with patch(
                "wormhole.handler.DNS_CACHE",
                {
                    "example.com": (["93.184.216.34"], 0, 200)
                },  # (ip_list, timestamp, ttl_expiration)
            ):
                # Mock time to make the cache valid (current time 100 < expiration time 200)
                with patch("wormhole.handler.time.time", return_value=100):
                    result = await _resolve_and_validate_host(
                        host, context, False
                    )

                    # Should return the cached IP list without calling resolver
                    assert result == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_dns_cache_expires_based_on_ttl(self, context):
        """Test that DNS cache expires based on TTL."""
        host = "example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the DNS cache to have an expired entry (current time 300 > expiration time 200)
            with patch.dict(
                "wormhole.handler.DNS_CACHE",
                {"example.com": (["93.184.216.34"], 0, 200)},
            ):
                # Mock time to make the cache expired
                with patch("wormhole.handler.time.time", return_value=300):
                    # Mock the resolver to return a valid IP and TTL
                    with patch("wormhole.handler.resolver") as mock_resolver:
                        mock_resolver.resolve_with_ttl = AsyncMock(
                            return_value=(
                                ["93.184.216.35"],
                                300,
                            )  # Different IP with 300s TTL
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

                                # Should return the IP list from resolver (new IP)
                                assert result == ["93.184.216.35"]

                                # Verify that the cache was updated with the new entry and its TTL
                                assert "example.com" in DNS_CACHE
                                cached_ips, _, ttl_expiration = DNS_CACHE[
                                    "example.com"
                                ]
                                assert cached_ips == ["93.184.216.35"]
                                # Should be set to expire in 300 seconds from now (time.time() + 300)
                                # Since we mocked time.time() to return 300, expiration should be 600
                                assert ttl_expiration == 600

    @pytest.mark.asyncio
    async def test_dns_cache_stores_min_ttl(self, context):
        """Test that DNS cache stores the minimum TTL from all records."""
        host = "example.com"

        # Clear the cache
        DNS_CACHE.clear()

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the resolver to return multiple IPs with different TTLs
            with patch("wormhole.handler.resolver") as mock_resolver:
                mock_resolver.resolve_with_ttl = AsyncMock(
                    return_value=(
                        ["93.184.216.34", "93.184.216.35"],
                        150,
                    )  # Two IPs with min TTL 150s
                )

                # Mock is_private_ip to return False for the IPs
                with patch(
                    "wormhole.handler.is_private_ip", return_value=False
                ):
                    # Mock has_public_ipv6 to return False
                    with patch(
                        "wormhole.handler.has_public_ipv6",
                        return_value=False,
                    ):
                        # Mock time.time() to return a fixed value for consistent testing
                        with patch(
                            "wormhole.handler.time.time", return_value=1000
                        ):
                            result = await _resolve_and_validate_host(
                                host, context, False
                            )

                            # Should return the IP list from resolver
                            assert "93.184.216.34" in result
                            assert "93.184.216.35" in result

                            # Verify that the cache was updated with the minimum TTL
                            assert "example.com" in DNS_CACHE
                            cached_ips, _, ttl_expiration = DNS_CACHE[
                                "example.com"
                            ]
                            assert len(cached_ips) == 2
                            # Expiration should be 150 seconds from our mocked time (1000 + 150 = 1150)
                            assert ttl_expiration == 1150

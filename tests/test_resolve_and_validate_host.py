#!/usr/bin/env python3
"""
Unit tests for the _resolve_and_validate_host function.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from wormhole.context import RequestContext
from wormhole.handler import _resolve_and_validate_host
from wormhole.safeguards import is_ad_domain, is_private_ip
from wormhole.resolver import resolver


class TestResolveAndValidateHost:
    """Test cases for the _resolve_and_validate_host function."""

    @pytest.fixture
    def context(self):
        """Create a test RequestContext."""
        ident = {"id": "test123", "client": "127.0.0.1"}
        return RequestContext(ident, verbose=1)

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_success(self, context):
        """Test successful resolution and validation of a host."""
        host = "example.com"

        # Mock the is_ad_domain function to return False
        with patch("wormhole.handler.is_ad_domain", return_value=False):
            # Mock the resolver to return a valid IP
            with patch("wormhole.handler.resolver") as mock_resolver:
                mock_resolver.resolve = AsyncMock(
                    return_value=["93.184.216.34"]
                )  # example.com

                # Mock is_private_ip to return False for the IP
                with patch(
                    "wormhole.handler.is_private_ip", return_value=False
                ):
                    # Mock has_public_ipv6 to return False
                    with patch(
                        "wormhole.handler.has_public_ipv6", return_value=False
                    ):
                        result = await _resolve_and_validate_host(
                            host, context, False
                        )

                        # Should return the IP list
                        assert result == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_resolve_and_validate_host_ad_domain_blocked(self, context):
        """Test that ad domains are blocked."""
        host = "ads.example.com"

        # Mock the is_ad_domain function to return True
        with patch("wormhole.handler.is_ad_domain", return_value=True):
            with pytest.raises(PermissionError) as exc_info:
                await _resolve_and_validate_host(host, context, False)

            assert "Blocked ad domain" in str(exc_info.value)

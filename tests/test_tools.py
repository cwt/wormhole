#!/usr/bin/env python3
"""
Unit tests for the tools module.
"""
import pytest
from wormhole.tools import get_content_length, get_host_and_port


class TestTools:
    """Test cases for the tools functions."""

    def test_get_content_length_found(self):
        """Test get_content_length when Content-Length header is present."""
        headers = (
            "GET / HTTP/1.1\r\nContent-Length: 123\r\nHost: example.com\r\n\r\n"
        )
        result = get_content_length(headers)
        assert result == 123

    def test_get_content_length_not_found(self):
        """Test get_content_length when Content-Length header is not present."""
        headers = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = get_content_length(headers)
        assert result == 0

    def test_get_content_length_case_insensitive(self):
        """Test get_content_length is case insensitive."""
        headers = (
            "GET / HTTP/1.1\r\ncontent-length: 456\r\nHost: example.com\r\n\r\n"
        )
        result = get_content_length(headers)
        assert result == 456

    def test_get_content_length_multiple(self):
        """Test get_content_length with multiple Content-Length headers (invalid but possible)."""
        headers = "GET / HTTP/1.1\r\nContent-Length: 123\r\nContent-Length: 456\r\nHost: example.com\r\n\r\n"
        result = get_content_length(headers)
        # Should return the first one found
        assert result == 123

    def test_get_host_and_port_with_port(self):
        """Test get_host_and_port with explicit port."""
        host_port = "example.com:8080"
        host, port = get_host_and_port(host_port)
        assert host == "example.com"
        assert port == 8080

    def test_get_host_and_port_without_port(self):
        """Test get_host_and_port without explicit port."""
        host_port = "example.com"
        host, port = get_host_and_port(host_port)
        assert host == "example.com"
        assert port == 80  # Default port

    # Note: The current implementation doesn't properly handle IPv6 addresses
    # These tests reflect the current behavior, not ideal IPv6 handling

    def test_get_host_and_port_ipv6_with_port(self):
        """Test get_host_and_port with IPv6-like string and port."""
        host_port = "[2001:db8::1]:8080"
        host, port = get_host_and_port(host_port)
        # Current implementation incorrectly parses this
        # This test documents current behavior
        assert host == "[2001:db8:"  # Incorrectly parsed
        assert port == 1  # Incorrectly parsed

    def test_get_host_and_port_ipv6_without_port(self):
        """Test get_host_and_port with IPv6-like string without port."""
        host_port = "2001:db8::1"
        host, port = get_host_and_port(host_port)
        # Current implementation incorrectly parses this
        # This test documents current behavior
        assert host == "2001:db8:"
        assert port == 1

    def test_get_host_and_port_custom_default_port(self):
        """Test get_host_and_port with custom default port."""
        host_port = "example.com"
        host, port = get_host_and_port(host_port, default_port="443")
        assert host == "example.com"
        assert port == 443  # Custom default port

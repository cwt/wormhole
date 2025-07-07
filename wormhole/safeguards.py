from functools import lru_cache
import ipaddress
import socket


@lru_cache(maxsize=1)
def has_public_ipv6() -> bool:
    """
    Checks if the current machine has a public, routable IPv6 address by
    attempting to connect a UDP socket to a public IPv6 DNS server.
    The result is cached to avoid repeated lookups.
    """
    s = None
    try:
        # Create a UDP socket for IPv6
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        # Attempt to connect to a known public IPv6 address (Google's public DNS).
        # This doesn't actually send any data. It just asks the OS to find a route.
        s.connect(("2001:4860:4860::8888", 80))
        # Get the local IP address the OS chose for the connection.
        local_ip_str = s.getsockname()[0]
        ip_obj = ipaddress.ip_address(local_ip_str)
        # If we get here, it means we have a routable IPv6.
        # The final check ensures it's not a link-local or other special address.
        return (
            not ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
        )
    except (OSError, socket.gaierror):
        # If an error occurs (e.g., no IPv6 connectivity), we don't have a public IPv6.
        return False
    finally:
        if s:
            s.close()


def is_private_ip(ip_str: str) -> bool:
    """
    Checks if a given IP address string is a private, reserved, or loopback address.

    This is a security measure to prevent the proxy from being used to access
    internal network resources (SSRF attacks).

    Args:
        ip_str: The IP address to check.

    Returns:
        True if the IP address is private/reserved, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback
    except ValueError:
        # If the string is not a valid IP address, we can't make a security
        # determination, so we conservatively block it.
        return True

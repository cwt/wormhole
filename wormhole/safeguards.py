from .logger import logger
from functools import lru_cache
import aiosqlite
import ipaddress
import socket
import sys

# A hardcoded default allowlist for most known safe domains.
DEFAULT_ALLOWLIST: set[str] = {
    "s3.amazonaws.com",  # Amazon S3 for static assets"
    "fonts.googleapis.com",  # Google Fonts
    "safebrowsing.googleapis.com",  # Google Safe Browsing for security
    "jnn-pa.googleapis.com",  # Google Cloud Private Service Connect Endpoint
    "www.googleapis.com",  # Google APIs (e.g., Maps, reCAPTCHA)
    "cdnjs.com",  # Cloudflare CDNJS
    "csp-reporting.cloudflare.com",  # Cloudflare CSP Reporting
    "static.cloudflareinsights.com",  # Cloudflare Web Analytics
    "vitals.vercel-insights.com",  # Vercel Web Vitals
    "cdn.jsdelivr.net",  # jsDelivr CDN for npm/GitHub packages
    "data.jsdelivr.com",  # jsDelivr API
    "esm.run",  # jsDelivr for JavaScript modules
    "unpkg.com",  # Unpkg CDN
    "twitter.com",  # Twitter for social media integration
    "x.com",  # X (formerly Twitter) for social media integration"
}

# The runtime sets are initialized. The allowlist starts with the defaults.
AD_BLOCK_SET: set[str] = set()
ALLOW_LIST_SET: set[str] = DEFAULT_ALLOWLIST.copy()


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


async def load_ad_block_db(path: str) -> int:
    """
    Loads a list of domains to block from a SQLite database into a global set
    for fast in-memory access.

    Args:
        path: The path to the SQLite database file.

    Returns:
        The number of unique domains loaded into the blocklist.
    """
    try:
        async with aiosqlite.connect(f"file:{path}?mode=ro", uri=True) as db:
            async with db.execute(
                "SELECT domain FROM blocked_domains"
            ) as cursor:
                async for row in cursor:
                    AD_BLOCK_SET.add(row[0])
    except Exception as e:
        logger.error(
            f"Could not load ad-block database from '{path}': {e}",
        )

    if AD_BLOCK_SET:
        # Calculate the total memory usage for the set and its contents
        set_size = sys.getsizeof(AD_BLOCK_SET)
        content_size = sum(sys.getsizeof(s) for s in AD_BLOCK_SET)
        total_size_mb = (set_size + content_size) / (1024 * 1024)
        logger.debug(
            f"Ad-block set memory usage: ~{total_size_mb:.2f} MB for {len(AD_BLOCK_SET)} domains"
        )

    return len(AD_BLOCK_SET)


def load_allowlist(path: str) -> int:
    """
    Loads domains from a user-provided file and adds them to the global allowlist set.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    ALLOW_LIST_SET.add(line.strip().lower())
    except FileNotFoundError:
        logger.error(f"Allowlist file not found at '{path}'")
    return len(ALLOW_LIST_SET)


def is_ad_domain(hostname: str) -> bool:
    """
    Checks if a hostname is blocked. It first checks against a runtime allowlist,
    then checks the main blocklist.
    """
    hostname_lower = hostname.lower()

    # 1. Check the allowlist first.
    if ALLOW_LIST_SET:
        if hostname_lower in ALLOW_LIST_SET:
            return False  # It's explicitly allowed
        # Check for parent domains in allowlist
        parts = hostname_lower.split(".")
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain in ALLOW_LIST_SET:
                return False  # A parent domain is allowed

    # 2. If not allowed, check the blocklist.
    if not AD_BLOCK_SET:
        return False

    if hostname_lower in AD_BLOCK_SET:
        return True

    parts = hostname_lower.split(".")
    for i in range(1, len(parts)):
        parent_domain = ".".join(parts[i:])
        if parent_domain in AD_BLOCK_SET:
            return True

    return False

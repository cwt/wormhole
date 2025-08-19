from .context import RequestContext
from .logger import logger, format_log_message as flm
from functools import lru_cache
import aiosqlite
import ipaddress
import socket
import sys

# A hardcoded default allowlist for most known safe domains.
DEFAULT_ALLOWLIST: set[str] = {
    "bit.ly",  # Bitly for URL shortening
    "azurewebsites.net",  # Azure Web App
    "studiostaticassetsprod.azureedge.net",  # Azure CDN for static files
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
    "bing.com",  # Bing for search functionality
    "t.co",  # Twitter domain shortening
    "twitter.com",  # Twitter for social media integration
    "x.com",  # X (formerly Twitter) for social media integration
}

# The runtime sets are initialized. The allowlist starts with the defaults.
AD_BLOCK_SET: set[str] = set()
ALLOW_LIST_SET: set[str] = DEFAULT_ALLOWLIST.copy()


@lru_cache(maxsize=1)
def has_public_ipv6() -> bool:
    """
    Checks if the current machine has a public, routable IPv6 address.

    This function attempts to connect a UDP socket to a public IPv6 DNS server to determine
    IPv6 connectivity. The result is cached to avoid repeated lookups.

    Returns:
        bool: True if a public, routable IPv6 address is available, False otherwise.
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
        ip_str (str): The IP address to check.

    Returns:
        bool: True if the IP address is private/reserved, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback
    except ValueError:
        # If the string is not a valid IP address, we can't make a security
        # determination, so we conservatively block it.
        return True


async def load_ad_block_db(
    path: str, host: str, context: RequestContext
) -> int:
    """
    Asynchronously loads a list of domains to block from a SQLite database into a global set for fast in-memory access.

    Args:
        path (str): The path to the SQLite database file.
        host (str): The host IP of the server, used for logging.
        context (RequestContext): The request context containing ident and verbose level.

    Returns:
        int: The number of unique domains loaded into the blocklist.
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
            flm(
                f"Could not load ad-block database from '{path}': {e}",
                context.ident,
                context.verbose,
            )
        )

    if AD_BLOCK_SET:
        # Calculate the total memory usage for the set and its contents
        set_size = sys.getsizeof(AD_BLOCK_SET)
        content_size = sum(sys.getsizeof(s) for s in AD_BLOCK_SET)
        total_size_mb = (set_size + content_size) / (1024 * 1024)
        logger.debug(
            flm(
                f"Ad-block set memory usage: ~{total_size_mb:.2f} MB for {len(AD_BLOCK_SET)} domains",
                context.ident,
                context.verbose,
            )
        )

    return len(AD_BLOCK_SET)


def load_allowlist(path: str, host: str, context: RequestContext) -> int:
    """
    Loads domains from a user-provided file and adds them to the global allowlist set.

    Args:
        path (str): The path to the file containing the allowlist domains.
        host (str): The host IP of the server, used for logging.
        context (RequestContext): The request context containing ident and verbose level.

    Returns:
        int: The number of unique domains loaded into the allowlist.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    ALLOW_LIST_SET.add(line.strip().lower())
    except FileNotFoundError:
        logger.error(
            flm(
                f"Allowlist file not found at '{path}'",
                context.ident,
                context.verbose,
            )
        )
    return len(ALLOW_LIST_SET)


def is_ad_domain(hostname: str) -> bool:
    """
    Checks if a hostname is blocked using a more specific block/allow logic.
    The blocklist is checked before the allowlist to allow for more granular control.

    The order of checks is:
    1. Exact match in blocklist -> Block
    2. Exact match in allowlist -> Allow
    3. Parent domain in blocklist -> Block
    4. Parent domain in allowlist -> Allow

    Args:
        hostname (str): The hostname to check.

    Returns:
        bool: True if the hostname is blocked, False otherwise.
    """
    hostname_lower = hostname.lower()

    # --- Highest Priority: Check for an exact match in the blocklist ---
    # This ensures that if 'ad-api.x.com' is specifically in the blocklist,
    # it is blocked immediately, even if 'x.com' is on the allowlist.
    if hostname_lower in AD_BLOCK_SET:
        return True

    # --- Second Priority: Check for an exact match in the allowlist ---
    if hostname_lower in ALLOW_LIST_SET:
        return False

    # --- Third Priority: Check for parent domains in the blocklist ---
    # This blocks subdomains of a blocked parent (e.g., if 'ad-server.com'
    # is blocked, 'analytics.ad-server.com' will also be blocked).
    parts = hostname_lower.split(".")
    for i in range(1, len(parts)):
        parent_domain = ".".join(parts[i:])
        if parent_domain in AD_BLOCK_SET:
            return True

    # --- Fourth Priority: Check for parent domains in the allowlist ---
    # This allows subdomains of an allowed parent (e.g., if 'x.com' is
    # allowed, 'www.x.com' will also be allowed), unless the subdomain
    # itself was caught by the blocklist checks above.
    for i in range(1, len(parts)):
        parent_domain = ".".join(parts[i:])
        if parent_domain in ALLOW_LIST_SET:
            return False

    # Default to not blocking if no specific rules match
    return False

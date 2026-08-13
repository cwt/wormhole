import re

# Regex patterns for extracting host and port from a string
# Handles bracketed IPv6 [::1]:port and regular host:port formats
REGEX_HOST_PORT = re.compile(r"\[?(.+?)\]?:([0-9]{1,5})$", re.IGNORECASE)


def get_host_and_port(
    hostname: str, default_port: str | None = None
) -> tuple[str, int]:
    """
    Extracts the host and port from a hostname string.

    Args:
        hostname (str): The hostname string to extract host and port from.
        default_port (str | None, optional): The default port to use if no port
                                             is found in the hostname. Defaults to None.

    Returns:
        tuple[str, int]: A tuple containing the host and port.
    """
    # Handle bracketed IPv6: [::1]:8080
    if hostname.startswith("[") and "]" in hostname:
        bracket_end = hostname.index("]")
        host = hostname[1:bracket_end]
        rest = hostname[bracket_end + 1 :]
        if rest.startswith(":"):
            port = int(rest[1:])
        else:
            port = int(default_port or "80")
        return host, port

    # Bare IPv6 addresses contain 2+ colons and have no port
    if hostname.count(":") >= 2:
        return hostname, int(default_port or "80")

    # Handle host:port
    if match := REGEX_HOST_PORT.search(hostname):
        host = match.group(1)
        port = int(match.group(2))
        return host, port

    return hostname, int(default_port or "80")


# Regex pattern for extracting Content-Length from HTTP headers
REGEX_CONTENT_LENGTH = re.compile(
    r"\r\nContent-Length: ([0-9]+)\r\n", re.IGNORECASE
)


def get_content_length(header: str) -> int:
    """
    Extracts the Content-Length from an HTTP header string.

    Args:
        header (str): The HTTP header string to extract Content-Length from.

    Returns:
        int: The Content-Length value, or 0 if not found.
    """
    if match := REGEX_CONTENT_LENGTH.search(header):
        return int(match.group(1))
    return 0

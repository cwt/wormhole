import re

# Regex patterns for extracting host and port from a string
REGEX_HOST = re.compile(r"(.+?):([0-9]{1,5})")


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
    if match := REGEX_HOST.search(hostname):
        return match.group(1), int(match.group(2))
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

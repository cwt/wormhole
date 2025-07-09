import re

REGEX_HOST = re.compile(r"(.+?):([0-9]{1,5})")

REGEX_CONTENT_LENGTH = re.compile(
    r"\r\nContent-Length: ([0-9]+)\r\n", re.IGNORECASE
)


def get_host_and_port(
    hostname: str, default_port: str | None = None
) -> tuple[str, int]:
    if match := REGEX_HOST.search(hostname):
        return match.group(1), int(match.group(2))
    return hostname, int(default_port or "80")


def get_content_length(header: str) -> int:
    if match := REGEX_CONTENT_LENGTH.search(header):
        return int(match.group(1))
    return 0

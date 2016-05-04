import re


REGEX_HOST = re.compile(
    r'(.+?):([0-9]{1,5})'
)

REGEX_CONTENT_LENGTH = re.compile(
    r'\r\nContent-Length: ([0-9]+)\r\n',
    re.IGNORECASE
)


def get_host_and_port(hostname, default_port=None):
    match = REGEX_HOST.search(hostname)
    if match:
        host = match.group(1)
        port = int(match.group(2))
    else:
        host = hostname
        port = int(default_port)
    return host, port


def get_content_length(header):
    match = REGEX_CONTENT_LENGTH.search(header)
    if match:
        return int(match.group(1))
    return 0

from base64 import b64decode
import asyncio

# A simple in-memory cache for the authentication list to avoid file I/O on every request.
_auth_list_cache: list[str] | None = None


def get_ident(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user: str | None = None,
) -> dict[str, str]:
    """Generates a unique identifier dictionary for a client connection."""
    peername = writer.get_extra_info("peername")
    client_ip = peername[0] if peername else "unknown"

    client_id = f"{user}@{client_ip}" if user else client_ip

    return {"id": hex(id(reader))[-6:], "client": client_id}


def _load_auth_file(auth_file_path: str) -> list[str]:
    """Loads and caches the list of 'user:password' strings from a file."""
    global _auth_list_cache
    if _auth_list_cache is None:
        try:
            with open(auth_file_path, "r", encoding="utf-8") as f:
                _auth_list_cache = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            # If the file doesn't exist, treat it as an empty auth list.
            _auth_list_cache = []
    return _auth_list_cache


async def send_auth_required_response(writer: asyncio.StreamWriter) -> None:
    """Sends a 407 Proxy Authentication Required response to the client."""
    response = (
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
        b'Proxy-Authenticate: Basic realm="Wormhole Proxy"\r\n'
        b"Connection: close\r\n"
        b"\r\n"
    )
    writer.write(response)
    await writer.drain()


async def verify_credentials(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    headers: list[str],
    auth_file_path: str,
) -> dict[str, str] | None:
    """
    Verifies the client's proxy credentials.

    Args:
        reader: The client's stream reader.
        writer: The client's stream writer.
        headers: The list of request headers.
        auth_file_path: The path to the authentication file.

    Returns:
        A new identifier dictionary including the username if authentication
        is successful, otherwise None.
    """
    auth_header = next(
        (h for h in headers if h.lower().startswith("proxy-authorization:")),
        None,
    )

    if auth_header:
        try:
            # Extract the Base64 encoded credentials.
            encoded_credentials = auth_header.split(" ", 2)[-1]
            # Decode and split into user:password.
            decoded_credentials = b64decode(encoded_credentials).decode("ascii")

            # Check if the credentials are in the valid list.
            if decoded_credentials in _load_auth_file(auth_file_path):
                username = decoded_credentials.split(":", 1)[0]
                return get_ident(reader, writer, user=username)

        except (IndexError, ValueError, TypeError):
            # This can happen with malformed auth headers.
            # We will treat it as a failed authentication attempt.
            pass

    # If authentication fails or is not provided, deny access.
    await send_auth_required_response(writer)
    return None

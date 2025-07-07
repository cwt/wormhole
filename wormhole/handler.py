from .logger import logger
from .tools import get_content_length, get_host_and_port
from socket import TCP_NODELAY
import asyncio


async def relay_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ident: dict[str, str],
    return_first_line: bool = False,
) -> bytes | None:
    """
    Relays data between a reader and a writer stream until EOF.

    Args:
        reader: The stream to read data from.
        writer: The stream to write data to.
        ident: A dictionary with 'id' and 'client' for logging.
        return_first_line: If True, captures and returns the first line.

    Returns:
        The first line of the stream as bytes if requested, otherwise None.
    """
    first_line: bytes | None = None
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break

            if return_first_line and first_line is None:
                if end_of_line := data.find(b"\r\n"):
                    first_line = data[:end_of_line]

            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError) as e:
        logger.debug(
            f"[{ident['id']}][{ident['client']}]: Relay network error: {e}"
        )
    except Exception as e:
        logger.error(
            f"[{ident['id']}][{ident['client']}]: Unexpected relay error: {e}",
            exc_info=True,
        )
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
    return first_line


# --- Core Request Handlers ---


async def process_https_tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    method: str,
    uri: str,
    ident: dict[str, str],
) -> None:
    """Establishes an HTTPS tunnel and relays data between client and server."""
    host, port = get_host_and_port(uri)
    server_reader = None
    server_writer = None

    try:
        # Establish a standard TCP connection to the target server.
        server_reader, server_writer = await asyncio.open_connection(host, port)

        # Signal the client that the tunnel is established.
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()

        # Use a TaskGroup for structured concurrency to relay data in both directions.
        async with asyncio.TaskGroup() as tg:
            tg.create_task(relay_stream(client_reader, server_writer, ident))
            tg.create_task(relay_stream(server_reader, client_writer, ident))

        logger.info(f"[{ident['id']}][{ident['client']}]: {method} 200 {uri}")

    except Exception as e:
        logger.error(
            f"[{ident['id']}][{ident['client']}]: {method} 502 {uri} ({e})"
        )
    finally:
        # Ensure server streams are closed if they were opened.
        if server_writer and not server_writer.is_closing():
            server_writer.close()
            await server_writer.wait_closed()


async def process_http_request(
    client_writer: asyncio.StreamWriter,
    method: str,
    uri: str,
    version: str,
    headers: list[str],
    payload: bytes,
    ident: dict[str, str],
) -> None:
    """Processes a standard HTTP request by forwarding it to the target server."""
    server_reader = None
    server_writer = None

    try:
        # Extract host from headers, defaulting to a safe value.
        host_header = next(
            (
                h.split(": ", 1)[1]
                for h in headers
                if h.lower().startswith("host:")
            ),
            "127.0.0.1",
        )
        host, port = get_host_and_port(host_header, default_port="80")

        # Rebuild headers for the target server.
        # - Remove proxy-specific headers.
        # - Ensure 'Connection: close' is set to prevent keep-alive issues.
        request_headers = [
            h for h in headers if not h.lower().startswith("proxy-")
        ]
        if not any(
            h.lower().startswith("connection:") for h in request_headers
        ):
            request_headers.append("Connection: close")

        # Reconstruct the request line and headers.
        path = uri.removeprefix(f"http://{host_header}")
        request_line = f"{method} {path} {version}".encode()
        headers_bytes = "\r\n".join(request_headers).encode()

        # Connect to the target server.
        server_reader, server_writer = await asyncio.open_connection(
            host, port, flags=TCP_NODELAY
        )

        # Send the reconstructed request.
        server_writer.write(
            request_line + b"\r\n" + headers_bytes + b"\r\n\r\n"
        )
        if payload:
            server_writer.write(payload)
        await server_writer.drain()

        # Relay the server's response back to the client.
        response_status_line = await relay_stream(
            server_reader, client_writer, ident, return_first_line=True
        )

        # Log the outcome.
        response_code = (
            int(response_status_line.split(b" ")[1])
            if response_status_line
            else 502
        )
        logger.info(
            f"[{ident['id']}][{ident['client']}]: {method} {response_code} {uri}"
        )

    except Exception as e:
        logger.error(
            f"[{ident['id']}][{ident['client']}]: {method} 502 {uri} ({e})"
        )
    finally:
        # Ensure server streams are closed if they were opened.
        if server_writer and not server_writer.is_closing():
            server_writer.close()
            await server_writer.wait_closed()


async def parse_request(
    client_reader: asyncio.StreamReader, max_retry: int, ident: dict[str, str]
) -> tuple[str, list[str], bytes] | tuple[None, None, None]:
    """
    Parses the initial request from the client.

    Reads from the client stream to get the request line, headers, and payload.
    Includes a simple retry mechanism for slow or incomplete initial reads.

    Returns:
        A tuple of (request_line, headers, payload) or (None, None, None) on failure.
    """
    try:
        # Read headers until the double CRLF, with a timeout to prevent hanging.
        header_bytes = await asyncio.wait_for(
            client_reader.readuntil(b"\r\n\r\n"), timeout=5.0
        )
    except (asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
        logger.debug(
            f"[{ident['id']}][{ident['client']}]: Failed to read initial request: {e}"
        )
        return None, None, None

    # Decode headers and split into lines.
    header_str = header_bytes.decode("ascii", errors="ignore")
    header_lines = header_str.strip().split("\r\n")
    request_line = header_lines[0]
    headers = header_lines[1:]

    # Read the payload if Content-Length is specified.
    payload = b""
    if content_length := get_content_length(header_str):
        try:
            payload = await client_reader.readexactly(content_length)
        except asyncio.IncompleteReadError:
            logger.debug(
                f"[{ident['id']}][{ident['client']}]: Incomplete payload read."
            )
            return None, None, None

    return request_line, headers, payload

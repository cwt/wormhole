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


async def _send_http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    version: str,
    headers: list[str],
    payload: bytes,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Helper function to connect and send an HTTP request."""
    request_line = f"{method} {path or '/'} {version}".encode()
    headers_bytes = "\r\n".join(headers).encode()

    server_reader, server_writer = await asyncio.open_connection(
        host, port, flags=TCP_NODELAY
    )

    server_writer.write(request_line + b"\r\n" + headers_bytes + b"\r\n\r\n")
    if payload:
        server_writer.write(payload)
    await server_writer.drain()

    return server_reader, server_writer


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
        # --- Determine target host and path ---
        host_header = next(
            (
                h.split(": ", 1)[1]
                for h in headers
                if h.lower().startswith("host:")
            ),
            None,
        )

        if host_header:
            host, port = get_host_and_port(host_header, default_port="80")
            path = uri
        elif uri.lower().startswith("http"):
            try:
                host_part = uri.split("/")[2]
                host, port = get_host_and_port(host_part, default_port="80")
                host_header = host_part
                path = "/" + "/".join(uri.split("/")[3:])
            except IndexError:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return
        else:
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            return

        # --- Attempt to upgrade to HTTP/1.1 if needed ---
        if version == "HTTP/1.0":
            logger.debug(
                f"[{ident['id']}][{ident['client']}]: Attempting to upgrade HTTP/1.0 request for {host_header} to HTTP/1.1"
            )

            # Prepare headers for HTTP/1.1
            headers_v1_1 = [
                h for h in headers if not h.lower().startswith("proxy-")
            ]
            if not any(h.lower().startswith("host:") for h in headers_v1_1):
                headers_v1_1.insert(0, f"Host: {host_header}")
            headers_v1_1 = [
                h
                for h in headers_v1_1
                if not h.lower().startswith("connection:")
            ]
            headers_v1_1.append("Connection: close")

            try:
                # Attempt 1: Try with HTTP/1.1
                server_reader, server_writer = await _send_http_request(
                    host, port, method, path, "HTTP/1.1", headers_v1_1, payload
                )
            except Exception as e:
                logger.warning(
                    f"[{ident['id']}][{ident['client']}]: HTTP/1.1 upgrade failed ({e}). Falling back to HTTP/1.0."
                )
                if server_writer and not server_writer.is_closing():
                    server_writer.close()
                    await server_writer.wait_closed()

                # Attempt 2: Fallback to original HTTP/1.0
                original_headers = [
                    h for h in headers if not h.lower().startswith("proxy-")
                ]
                original_headers = [
                    h
                    for h in original_headers
                    if not h.lower().startswith("connection:")
                ]
                original_headers.append("Connection: close")

                server_reader, server_writer = await _send_http_request(
                    host,
                    port,
                    method,
                    path,
                    "HTTP/1.0",
                    original_headers,
                    payload,
                )
        else:
            # Original request was already HTTP/1.1 or newer
            final_headers = [
                h for h in headers if not h.lower().startswith("proxy-")
            ]
            if not any(h.lower().startswith("host:") for h in final_headers):
                final_headers.insert(0, f"Host: {host_header}")
            final_headers = [
                h
                for h in final_headers
                if not h.lower().startswith("connection:")
            ]
            final_headers.append("Connection: close")

            server_reader, server_writer = await _send_http_request(
                host, port, method, path, version, final_headers, payload
            )

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
        if not client_writer.is_closing():
            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
            except ConnectionError:
                pass
    finally:
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

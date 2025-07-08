from .logger import logger
from .safeguards import has_public_ipv6, is_private_ip, is_ad_domain
from .tools import get_content_length, get_host_and_port
from socket import TCP_NODELAY
import asyncio
import ipaddress
import random
import time

# --- DNS Cache for Performance ---
DNS_CACHE: dict[str, tuple[str, float]] = {}
DNS_CACHE_TTL: int = 300  # Cache DNS results for 5 minutes

# --- Modernized Relay Stream Function ---


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
        logger.exception(
            f"[{ident['id']}][{ident['client']}]: Unexpected relay error: {e}",
            exc_info=True,
        )
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
    return first_line


async def _resolve_and_validate_host(host: str, allow_private: bool) -> str:
    """
    Resolves a hostname to an IP, validates it against private ranges, and caches it.
    Supports DNS load balancing and prioritizes IPv6 if available.
    Raises:
        PermissionError: If all resolved IPs are private/reserved addresses.
        OSError: If the host cannot be resolved.
    """
    # Ad-block check
    if is_ad_domain(host):
        raise PermissionError(f"Blocked ad domain: {host}")

    # Check cache first
    if host in DNS_CACHE:
        ip, timestamp = DNS_CACHE[host]
        if time.time() - timestamp < DNS_CACHE_TTL:
            logger.debug(
                f"DNS cache hit for '{host}'. ({len(DNS_CACHE)} hosts cached)"
            )
            return ip

    # Resolve hostname
    loop = asyncio.get_running_loop()
    try:
        addr_info_list = await loop.getaddrinfo(host, None, family=0)
        resolved_ips = {
            info[4][0] for info in addr_info_list
        }  # Use a set for uniqueness
    except OSError as e:
        raise OSError(f"Failed to resolve host: {host}") from e

    # Security Check and IP version separation
    public_ipv4s = []
    public_ipv6s = []
    for ip_str in resolved_ips:
        # Bypass the private IP check if the flag is set.
        if allow_private or not is_private_ip(ip_str):
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.version == 4:
                    public_ipv4s.append(ip_str)
                elif ip_obj.version == 6:
                    public_ipv6s.append(ip_str)
            except ValueError:
                continue  # Ignore invalid IP strings

    # Prioritization Logic
    chosen_ip = None
    if has_public_ipv6() and public_ipv6s:
        logger.debug(f"Host has public IPv6. Prioritizing from: {public_ipv6s}")
        chosen_ip = random.choice(public_ipv6s)
    elif public_ipv4s:
        logger.debug(
            f"No public IPv6 available/resolved. Using IPv4 from: {public_ipv4s}"
        )
        chosen_ip = random.choice(public_ipv4s)
    elif public_ipv6s:  # Fallback to IPv6 if it's all we have
        logger.debug(f"Only IPv6 resolved. Using from: {public_ipv6s}")
        chosen_ip = random.choice(public_ipv6s)
    else:
        raise PermissionError(
            f"Blocked access to '{host}' as it resolved to only private/reserved IPs."
        )

    # Update cache
    DNS_CACHE[host] = (chosen_ip, time.time())
    logger.debug(
        f"DNS cache miss for '{host}'. Chose {chosen_ip}. Caching. ({len(DNS_CACHE)} hosts cached)"
    )
    return chosen_ip


# --- Core Request Handlers ---


async def process_https_tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    method: str,
    uri: str,
    ident: dict[str, str],
    allow_private: bool,
) -> None:
    """Establishes an HTTPS tunnel and relays data between client and server."""
    host, port = get_host_and_port(uri)
    server_reader = None
    server_writer = None

    try:
        # Resolve, validate, and cache the host's IP address.
        validated_host_ip = await _resolve_and_validate_host(
            host, allow_private
        )

        # Establish a standard TCP connection to the target server.
        server_reader, server_writer = await asyncio.open_connection(
            validated_host_ip, port
        )

        # Signal the client that the tunnel is established.
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()

        # Use a TaskGroup for structured concurrency to relay data in both directions.
        async with asyncio.TaskGroup() as tg:
            tg.create_task(relay_stream(client_reader, server_writer, ident))
            tg.create_task(relay_stream(server_reader, client_writer, ident))

        logger.info(f"[{ident['id']}][{ident['client']}]: {method} 200 {uri}")

    except PermissionError as e:
        logger.warning(
            f"[{ident['id']}][{ident['client']}]: {method} 403 {uri} ({e})"
        )
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
    except Exception as e:
        logger.exception(
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
    allow_private: bool,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Helper function to connect and send an HTTP request."""
    request_line = f"{method} {path or '/'} {version}".encode()
    headers_bytes = "\r\n".join(headers).encode()

    # Resolve, validate, and cache the host's IP address.
    validated_host_ip = await _resolve_and_validate_host(host, allow_private)

    server_reader, server_writer = await asyncio.open_connection(
        validated_host_ip, port, flags=TCP_NODELAY
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
    allow_private: bool,
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
                    host,
                    port,
                    method,
                    path,
                    "HTTP/1.1",
                    headers_v1_1,
                    payload,
                    allow_private,
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
                    allow_private,
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
                host,
                port,
                method,
                path,
                version,
                final_headers,
                payload,
                allow_private,
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

    except PermissionError as e:
        logger.warning(
            f"[{ident['id']}][{ident['client']}]: {method} 403 {uri} ({e})"
        )
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
    except Exception as e:
        logger.exception(
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

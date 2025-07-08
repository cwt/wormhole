from .logger import logger
from .safeguards import has_public_ipv6, is_ad_domain, is_private_ip
from .tools import get_content_length, get_host_and_port
import asyncio
import ipaddress
import random
import time

# --- DNS Cache for Performance ---
DNS_CACHE: dict[str, tuple[list[str], float]] = {}
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
        )
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
    return first_line


async def _resolve_and_validate_host(
    host: str, allow_private: bool
) -> list[str]:
    """
    Resolves a hostname to a list of IPs, validates them, and caches the list.
    Supports DNS load balancing and prioritizes IPv6 if available.
    Raises:
        PermissionError: If the host is an ad domain or resolves to only private IPs.
        OSError: If the host cannot be resolved.
    """
    # Ad-block check
    if is_ad_domain(host):
        raise PermissionError(f"Blocked ad domain: {host}")

    # Check cache first
    if host in DNS_CACHE:
        ip_list, timestamp = DNS_CACHE[host]
        if time.time() - timestamp < DNS_CACHE_TTL:
            logger.debug(
                f"DNS cache hit for '{host}'. ({len(DNS_CACHE)} hosts cached)"
            )
            return ip_list

    # Resolve hostname
    loop = asyncio.get_running_loop()
    try:
        addr_info_list = await loop.getaddrinfo(host, None, family=0)
        resolved_ips = {info[4][0] for info in addr_info_list}
    except OSError as e:
        raise OSError(f"Failed to resolve host: {host}") from e

    # Security Check and IP version separation
    valid_ipv4s, valid_ipv6s = [], []
    for ip_str in resolved_ips:
        # Bypass the private IP check if the flag is set.
        if allow_private or not is_private_ip(ip_str):
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.version == 4:
                    valid_ipv4s.append(ip_str)
                elif ip_obj.version == 6:
                    valid_ipv6s.append(ip_str)
            except ValueError:
                continue

    # Prioritization and shuffling for load balancing
    final_ip_list = []
    if has_public_ipv6() and valid_ipv6s:
        logger.debug(
            f"Host has public IPv6. Prioritizing {len(valid_ipv6s)} IPv6 addresses."
        )
        random.shuffle(valid_ipv6s)
        final_ip_list.extend(valid_ipv6s)

    if valid_ipv4s:
        random.shuffle(valid_ipv4s)
        final_ip_list.extend(valid_ipv4s)

    # Fallback to IPv6 if it's all we have and wasn't prioritized
    if not final_ip_list and valid_ipv6s:
        random.shuffle(valid_ipv6s)
        final_ip_list.extend(valid_ipv6s)

    if not final_ip_list:
        raise PermissionError(
            f"Blocked access to '{host}' as it resolved to only private/reserved IPs."
        )

    # Update cache
    DNS_CACHE[host] = (final_ip_list, time.time())
    logger.debug(
        f"DNS cache miss for '{host}'. Resolved to {final_ip_list}. Caching. ({len(DNS_CACHE)} hosts cached)"
    )
    return final_ip_list


async def _create_connection_with_retries(
    ip_list: list[str], port: int, ident: dict[str, str]
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Tries to connect to a list of IPs with a fast timeout and retry mechanism.
    """
    max_attempts = 3
    timeout = 5  # seconds
    last_error = None

    # Create a list of connection targets to try, ensuring we don't exceed max_attempts
    targets_to_try = (ip_list * (max_attempts // len(ip_list) + 1))[
        :max_attempts
    ]

    for i, ip in enumerate(targets_to_try):
        attempt = i + 1
        logger.debug(
            f"Connection attempt {attempt}/{max_attempts} to {ip}:{port}"
        )
        try:
            # Use a short timeout for each connection attempt
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            logger.debug(
                f"Successfully connected to {ip}:{port} on attempt {attempt}"
            )
            return reader, writer
        except (OSError, asyncio.TimeoutError) as e:
            last_error = e
            logger.warning(
                f"Connection to {ip}:{port} failed on attempt {attempt}: {e}"
            )

    raise OSError(
        f"Failed to connect after {max_attempts} attempts. Last error: {last_error}"
    )


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
        # Resolve and validate the host to get a list of potential IPs.
        ip_list = await _resolve_and_validate_host(host, allow_private)

        # Attempt to connect to one of the IPs with retry logic.
        server_reader, server_writer = await _create_connection_with_retries(
            ip_list, port, ident
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
    ip_list: list[str],
    port: int,
    method: str,
    path: str,
    version: str,
    headers: list[str],
    payload: bytes,
    ident: dict[str, str],
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Helper function to connect and send an HTTP request."""
    request_line = f"{method} {path or '/'} {version}".encode()
    headers_bytes = "\r\n".join(headers).encode()

    # Attempt to connect to one of the IPs with retry logic.
    server_reader, server_writer = await _create_connection_with_retries(
        ip_list, port, ident
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

        # Resolve and validate the host to get a list of potential IPs.
        ip_list = await _resolve_and_validate_host(host, allow_private)

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
                    ip_list,
                    port,
                    method,
                    path,
                    "HTTP/1.1",
                    headers_v1_1,
                    payload,
                    ident,
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
                    ip_list,
                    port,
                    method,
                    path,
                    "HTTP/1.0",
                    original_headers,
                    payload,
                    ident,
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
                ip_list,
                port,
                method,
                path,
                version,
                final_headers,
                payload,
                ident,
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

from .logger import logger, format_log_message as flm
from .safeguards import has_public_ipv6, is_ad_domain, is_private_ip
from .tools import get_content_length, get_host_and_port
from .resolver import resolver
from .context import RequestContext
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
    context: RequestContext,
    return_first_line: bool = False,
) -> bytes | None:
    """
    Relays data from a reader to a writer.

    Reads from the reader until the end of the stream is reached and writes
    the data to the writer. Handles any exceptions that may occur during the process.

    Args:
        reader (asyncio.StreamReader): The reader to read data from.
        writer (asyncio.StreamWriter): The writer to write data to.
        context (RequestContext): The request context containing ident and verbose level.
        return_first_line (bool, optional): Whether to return the first line of data. Defaults to False.

    Returns:
        bytes: The first line of data if return_first_line is True, otherwise None.
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
            flm(f"Relay network error: {e}", context.ident, context.verbose)
        )
    except Exception as e:
        msg = flm(
            f"Unexpected relay error: {e}", context.ident, context.verbose
        )
        if context.verbose > 2:  # Show full traceback only for -vv
            logger.exception(msg)
        else:
            logger.error(msg)
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()
    return first_line


async def _resolve_and_validate_host(
    host: str, context: RequestContext, allow_private: bool
) -> list[str]:
    """
    Resolves a hostname to a list of valid IPs, prioritizes IPv6, caches the results,
    and handles DNS load balancing.

    Uses aiodns via a custom resolver that respects the local hosts file.

    Args:
        host (str): The hostname to resolve.
        context (RequestContext): The request context containing ident and verbose level.
        allow_private (bool): Whether to allow private IP addresses.

    Returns:
        list[str]: A list of valid IP addresses.

    Raises:
        PermissionError: If the host is an ad domain or resolves to only private IPs.
        OSError: If the host cannot be resolved.
    """
    # Ad-block check
    if is_ad_domain(host):
        raise PermissionError(f"Blocked ad domain")

    # Check cache first
    if host in DNS_CACHE:
        ip_list, timestamp = DNS_CACHE[host]
        if time.time() - timestamp < DNS_CACHE_TTL:
            logger.debug(
                flm(
                    f"DNS cache hit for '{host}'. ({len(DNS_CACHE)} hosts cached)",
                    context.ident,
                    context.verbose,
                )
            )
            return ip_list

    # Resolve hostname using aiodns resolver
    try:
        resolved_ips = await resolver.resolve(host)
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
            flm(
                f"Host has public IPv6. Prioritizing {len(valid_ipv6s)} IPv6 addresses.",
                context.ident,
                context.verbose,
            )
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
        flm(
            (
                f"DNS cache miss for '{host}'. "
                f"Resolved to {final_ip_list}. Caching. "
                f"({len(DNS_CACHE)} hosts cached)"
            ),
            context.ident,
            context.verbose,
        )
    )
    return final_ip_list


async def _create_fastest_connection(
    ip_list: list[str],
    port: int,
    context: RequestContext,
    timeout: int = 5,
    max_attempts: int = 3,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Helper function to create the fastest connection to the target server.

    Args:
        ip_list (list[str]): List of IP addresses to try.
        port (int): Port number to connect to.
        context (RequestContext): The request context containing ident and verbose level.
        timeout (int, optional): Connection timeout in seconds. Defaults to 5.
        max_attempts (int, optional): Maximum number of attempts. Defaults to 3.

    Returns:
        tuple[asyncio.StreamReader, asyncio.StreamWriter]: Reader and writer for the server connection.
    """
    last_error = None

    for attempt in range(max_attempts):
        logger.debug(
            flm(
                f"Connection attempt {attempt + 1}/{max_attempts} to {ip_list}",
                context.ident,
                context.verbose,
            )
        )

        tasks = {
            asyncio.create_task(
                asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                ),
                name=ip,
            )
            for ip in ip_list
        }

        # Inner loop for the "Happy Eyeballs" race
        while tasks:
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )

            for task in done:
                try:
                    reader, writer = task.result()
                    # On success, cancel pending tasks and return the connection
                    for p_task in pending:
                        p_task.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    peer = writer.get_extra_info("peername")
                    logger.debug(
                        flm(
                            f"Successfully established fastest connection to {peer[0]}:{peer[1]}",
                            context.ident,
                            context.verbose,
                        )
                    )
                    return reader, writer
                except (
                    OSError,
                    asyncio.TimeoutError,
                    asyncio.CancelledError,
                ) as e:
                    ip = task.get_name()
                    logger.debug(
                        flm(
                            f"Connection to {ip}:{port} failed within race: {e}",
                            context.ident,
                            context.verbose,
                        )
                    )
                    last_error = e

            tasks = pending

        # If the inner loop finishes, all IPs failed in this attempt.
        # Wait before the next retry, if any.
        if attempt < max_attempts - 1:
            logger.warning(
                flm(
                    f"All connections failed on attempt {attempt + 1}. Retrying in 1 second...",
                    context.ident,
                    context.verbose,
                )
            )
            await asyncio.sleep(1)

    raise OSError(
        f"All connection attempts failed after {max_attempts} retries. Last error: {last_error}"
    )


# --- Core Request Handlers ---


async def process_https_tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    method: str,
    uri: str,
    ident: dict[str, str],
    allow_private: bool,
    max_attempts: int = 3,
    verbose: int = 0,
) -> None:
    """
    Establishes an HTTPS tunnel between client and server.

    Reads the client's initial request, resolves the host, establishes a connection,
    and relays data between the client and server in both directions. Handles
    exceptions and logs the outcome.

    Args:
        client_reader (asyncio.StreamReader): The client's input stream.
        client_writer (asyncio.StreamWriter): The client's output stream.
        method (str): The HTTP method used in the request.
        uri (str): The URI of the request.
        ident (dict[str, str]): A dictionary containing the unique identifier and client details.
        allow_private (bool): Whether to allow private IP addresses.
        max_attempts (int, optional): Maximum number of attempts to establish a connection. Defaults to 3.
        verbose (int, optional): Verbosity level for logging. Defaults to 0.

    Returns:
        None
    """
    host, port = get_host_and_port(uri)
    server_reader = None
    server_writer = None

    # Create a request context to reduce parameter passing
    context = RequestContext(ident, verbose)

    try:
        # Resolve and validate the host to get a list of potential IPs.
        ip_list = await _resolve_and_validate_host(host, context, allow_private)
        server_reader, server_writer = await _create_fastest_connection(
            ip_list, port, context, max_attempts=max_attempts
        )

        # Signal the client that the tunnel is established.
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()

        # Use a TaskGroup for structured concurrency to relay data in both directions.
        async with asyncio.TaskGroup() as tg:
            tg.create_task(relay_stream(client_reader, server_writer, context))
            tg.create_task(relay_stream(server_reader, client_writer, context))

        logger.info(flm(f"{method} 200 {uri}", context.ident, context.verbose))

    except PermissionError as e:
        logger.warning(
            flm(f"{method} 403 {uri} ({e})", context.ident, context.verbose)
        )
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()

    except Exception as e:
        msg = flm(f"{method} 502 {uri} ({e})", context.ident, context.verbose)
        if context.verbose > 2:  # Show full traceback only for -vv
            logger.exception(msg)
        else:
            logger.error(msg)

    finally:
        # Ensure server streams are closed if they were opened.
        if server_writer is not None and not server_writer.is_closing():
            server_writer.close()
            wc = getattr(server_writer, "wait_closed", None)
            if callable(wc):
                result = wc()
                if asyncio.iscoroutine(result):
                    await result


async def _send_http_request(
    ip_list: list[str],
    port: int,
    method: str,
    path: str,
    version: str,
    headers: list[str],
    payload: bytes,
    context: RequestContext,
    max_attempts: int = 3,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Helper function to connect and send an HTTP request.

    Args:
        ip_list (list[str]): List of IP addresses to try.
        port (int): Port number to connect to.
        method (str): HTTP method (e.g., GET, POST).
        path (str): Request path.
        version (str): HTTP version (e.g., HTTP/1.0, HTTP/1.1).
        headers (list[str]): List of HTTP headers.
        payload (bytes): Request payload.
        context (RequestContext): The request context containing ident and verbose level.
        max_attempts (int, optional): Maximum number of attempts to connect. Defaults to 3.

    Returns:
        tuple[asyncio.StreamReader, asyncio.StreamWriter]: A tuple of server reader and writer.
    """
    request_line = f"{method} {path or '/'} {version}".encode()
    headers_bytes = "\r\n".join(headers).encode()
    server_reader, server_writer = await _create_fastest_connection(
        ip_list, port, context, max_attempts=max_attempts
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
    max_attempts: int = 3,
    verbose: int = 0,
) -> None:
    """
    Process an HTTP request by forwarding it to a target server and relaying
    the response back to the client, handling retries if necessary and upgrading
    the request to HTTP/1.1 if it's HTTP/1.0.

    Args:
        client_writer (asyncio.StreamWriter): The writer for the client connection.
        method (str): The HTTP method (e.g., GET, POST).
        uri (str): The request URI.
        version (str): The HTTP version.
        headers (list[str]): The list of HTTP headers.
        payload (bytes): The request payload.
        ident (dict[str, str]): A dictionary containing the unique identifier and client details.
        allow_private (bool): Flag to allow private IP addresses.
        max_attempts (int, optional): Maximum number of attempts to connect. Defaults to 3.
        verbose (int, optional): Verbosity level. Defaults to 0.

    Returns:
        None
    """
    server_reader = None
    server_writer = None

    # Create a request context to reduce parameter passing
    context = RequestContext(ident, verbose)

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
        ip_list = await _resolve_and_validate_host(host, context, allow_private)

        # --- Attempt to upgrade to HTTP/1.1 if needed ---
        if version == "HTTP/1.0":
            logger.debug(
                flm(
                    f"Attempting to upgrade HTTP/1.0 request for {host_header} to HTTP/1.1",
                    context.ident,
                    context.verbose,
                )
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
                    context,
                    max_attempts,
                )
            except Exception as e:
                logger.warning(
                    flm(
                        f"HTTP/1.1 upgrade failed ({e}). Falling back to HTTP/1.0.",
                        context.ident,
                        context.verbose,
                    )
                )
                if server_writer and not server_writer.is_closing():
                    server_writer.close()
                    wc = getattr(server_writer, "wait_closed", None)
                    if callable(wc):
                        result = wc()
                        if asyncio.iscoroutine(result):
                            await result

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
                    context,
                    max_attempts,
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
                context,
                max_attempts,
            )

        # Relay the server's response back to the client.
        response_status_line = await relay_stream(
            server_reader,
            client_writer,
            context,
            return_first_line=True,
        )

        # Log the outcome.
        response_code = (
            int(response_status_line.split(b" ")[1])
            if response_status_line
            else 502
        )
        logger.info(
            flm(
                f"{method} {response_code} {uri}",
                context.ident,
                context.verbose,
            )
        )

    except PermissionError as e:
        logger.warning(
            flm(f"{method} 403 {uri} ({e})", context.ident, context.verbose)
        )
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()

    except Exception as e:
        msg = flm(f"{method} 502 {uri} ({e})", context.ident, context.verbose)
        if context.verbose > 2:  # Show full traceback only for -vv
            logger.exception(msg)
        else:
            logger.error(msg)
        if not client_writer.is_closing():
            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
            except ConnectionError:
                pass  # Ignore if client is already closed

    finally:
        if server_writer and not server_writer.is_closing():
            server_writer.close()
            await server_writer.wait_closed()


async def parse_request(
    client_reader: asyncio.StreamReader, context: RequestContext
) -> tuple[str, list[str], bytes] | tuple[None, None, None]:
    """
    Parse an HTTP request from the client.

    Reads the request line and headers from the client, and optionally
    reads the payload if Content-Length is specified.

    Args:
        client_reader (asyncio.StreamReader): The reader for the client connection.
        context (RequestContext): The request context containing ident and verbose level.

    Returns:
        tuple[str, list[str], bytes] | tuple[None, None, None]:
        A tuple containing the request line, headers, and payload,
        or None if parsing fails.
    """
    try:
        # Read headers until the double CRLF, with a timeout to prevent hanging.
        header_bytes = await asyncio.wait_for(
            client_reader.readuntil(b"\r\n\r\n"), timeout=5.0
        )
    except (asyncio.IncompleteReadError, asyncio.TimeoutError) as e:
        logger.debug(
            flm(
                f"Failed to read initial request: {e}",
                context.ident,
                context.verbose,
            )
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
                flm(f"Incomplete payload read.", context.ident, context.verbose)
            )
            return None, None, None

    return request_line, headers, payload

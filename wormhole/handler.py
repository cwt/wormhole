import asyncio
from socket import TCP_NODELAY
from logger import Logger
from tools import get_content_length, get_host_and_port


async def relay_stream(
    stream_reader: asyncio.StreamReader,
    stream_writer: asyncio.StreamWriter,
    ident: dict[str, str],
    return_first_line: bool = False,
) -> bytes | None:
    # Initialize logger for debugging and info logging
    logger = Logger().get_logger()
    first_line = None

    # Relay data between reader and writer with proper async handling
    while True:
        try:
            # Read data asynchronously from the stream
            line = await stream_reader.read(4096)
            if not line:
                break

            # Write data and ensure buffer is flushed asynchronously
            stream_writer.write(line)
            await stream_writer.drain()  # Ensure no blocking if buffer is full
        except Exception as ex:
            # Log any exceptions during relay
            logger.debug(
                f"[{ident['id']}][{ident['client']}]: {ex.__class__.__name__}: {' '.join(map(str, ex.args))}"
            )
            break
        else:
            # Capture first line if requested
            if return_first_line and first_line is None:
                first_line = line[: line.find(b"\r\n")]

    return first_line


async def process_https(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    request_method: str,
    uri: str,
    ident: dict[str, str],
) -> None:
    # Initialize logger for tracking request status
    logger = Logger().get_logger()
    host, port = get_host_and_port(uri)

    try:
        # Open connection to target server without SSL (tunneling)
        req_reader, req_writer = await asyncio.open_connection(host, port, ssl=False)

        # Send success response to client
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await client_writer.drain()  # Ensure response is sent

        # Relay data bidirectionally between client and target server
        await asyncio.gather(
            relay_stream(client_reader, req_writer, ident),
            relay_stream(req_reader, client_writer, ident),
        )

        # Log successful tunneling
        logger.info(f"[{ident['id']}][{ident['client']}]: {request_method} 200 {uri}")
    except Exception as ex:
        # Log errors during HTTPS processing
        logger.error(
            f"[{ident['id']}][{ident['client']}]: {request_method} 502 {uri} ({ex.__class__.__name__}: {' '.join(map(str, ex.args))})"
        )


async def process_http(
    client_writer: asyncio.StreamWriter,
    request_method: str,
    uri: str,
    http_version: str,
    headers: list[str],
    payload: bytes,
    ident: dict[str, str],
) -> None:
    # Initialize logger for request tracking
    logger = Logger().get_logger()
    hostname = "127.0.0.1"
    request_headers = []
    has_connection = False

    # Process headers efficiently
    for header in headers:
        if ": " in header:
            name, value = header.split(": ", 1)
            match name.lower():
                case "host":
                    hostname = value
                case "connection":
                    has_connection = True
                    request_headers.append(
                        "Connection: close"
                        if value.lower() in ("keep-alive", "persist")
                        else header
                    )
                case "proxy-connection":
                    continue
                case _:
                    request_headers.append(header)

    if not has_connection:
        request_headers.append("Connection: close")

    # Construct new request path and headers
    path = uri.removeprefix(f"http://{hostname}")
    new_head = f"{request_method} {path} {http_version}"
    host, port = get_host_and_port(hostname, "80")

    try:
        # Open connection to target server with TCP_NODELAY for performance
        req_reader, req_writer = await asyncio.open_connection(
            host, port, flags=TCP_NODELAY
        )

        # Write request headers and payload asynchronously
        req_writer.write(f"{new_head}\r\nHost: {hostname}\r\n".encode())
        for header in request_headers:
            req_writer.write(f"{header}\r\n".encode())
        req_writer.write(b"\r\n")
        if payload:
            req_writer.write(payload)
        await req_writer.drain()  # Ensure all data is sent

        # Relay response and get status code
        response_status = await relay_stream(req_reader, client_writer, ident, True)
        response_code = (
            int(response_status.decode("ascii").split(" ")[1])
            if response_status
            else 502
        )

        # Log request outcome
        logger.info(
            f"[{ident['id']}][{ident['client']}]: {request_method} {response_code} {uri}"
        )
    except Exception as ex:
        # Log errors during HTTP processing
        logger.error(
            f"[{ident['id']}][{ident['client']}]: {request_method} 502 {uri} ({ex.__class__.__name__}: {' '.join(map(str, ex.args))})"
        )


async def process_request(
    client_reader: asyncio.StreamReader, max_retry: int, ident: dict[str, str]
) -> tuple[str, list[str], bytes]:
    # Initialize logger for debugging
    logger = Logger().get_logger()
    payload = b""
    retry = 0

    # Read headers until double CRLF efficiently
    try:
        header_bytes = await client_reader.readuntil(b"\r\n\r\n")
        header = header_bytes.decode("ascii")
    except asyncio.IncompleteReadError:
        # Retry on incomplete read up to max_retry
        while retry < max_retry:
            retry += 1
            await asyncio.sleep(0.1)
            try:
                header_bytes = await client_reader.readuntil(b"\r\n\r\n")
                header = header_bytes.decode("ascii")
                break
            except asyncio.IncompleteReadError:
                continue
        else:
            # If retries exhausted, return empty result
            return "", [], b""

    # Extract content length and read payload
    content_length = get_content_length(header)
    if content_length > 0:
        payload = await client_reader.readexactly(content_length)

    # Split headers into lines
    header_lines = header.split("\r\n")
    return header_lines[0], header_lines[1:-1] if len(header_lines) > 2 else [], payload

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
    logger = Logger().get_logger()

    first_line = None
    while True:
        try:
            line = await stream_reader.read(4096)
            if not line:
                break
            stream_writer.write(line)
        except Exception as ex:

            logger.debug(
                f"[{ident['id']}][{ident['client']}]: {ex.__class__.__name__}: {' '.join(map(str, ex.args))}"
            )
            break

        else:
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
    logger = Logger().get_logger()
    host, port = get_host_and_port(uri)
    try:
        req_reader, req_writer = await asyncio.open_connection(host, port, ssl=False)
        client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await asyncio.gather(
            relay_stream(client_reader, req_writer, ident),
            relay_stream(req_reader, client_writer, ident),
        )

        logger.info(f"[{ident['id']}][{ident['client']}]: {request_method} 200 {uri}")
    except Exception as ex:
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
    logger = Logger().get_logger()
    hostname = "127.0.0.1"
    request_headers = []
    has_connection = False

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

    path = uri.removeprefix(f"http://{hostname}")
    new_head = f"{request_method} {path} {http_version}"
    host, port = get_host_and_port(hostname, "80")

    try:

        req_reader, req_writer = await asyncio.open_connection(
            host, port, flags=TCP_NODELAY
        )
        req_writer.write(f"{new_head}\r\nHost: {hostname}\r\n".encode())
        for header in request_headers:
            req_writer.write(f"{header}\r\n".encode())
        req_writer.write(b"\r\n")
        if payload:
            req_writer.write(payload)
        await req_writer.drain()

        response_status = await relay_stream(req_reader, client_writer, ident, True)
        response_code = (
            int(response_status.decode("ascii").split(" ")[1])
            if response_status
            else 502
        )
        logger.info(
            f"[{ident['id']}][{ident['client']}]: {request_method} {response_code} {uri}"
        )
    except Exception as ex:
        logger.error(
            f"[{ident['id']}][{ident['client']}]: {request_method} 502 {uri} ({ex.__class__.__name__}: {' '.join(map(str, ex.args))})"
        )


async def process_request(
    client_reader: asyncio.StreamReader, max_retry: int, ident: dict[str, str]
) -> tuple[str, list[str], bytes]:

    logger = Logger().get_logger()
    header = ""
    payload = b""
    retry = 0

    while True:
        line = await client_reader.readline()
        if not line:
            if not header and retry < max_retry:
                retry += 1
                await asyncio.sleep(0.1)

                continue
            break
        if line == b"\r\n":

            break
        header += line.decode()

    content_length = get_content_length(header)
    while len(payload) < content_length:
        payload += await client_reader.read(4096)

    header_lines = header.split("\r\n")
    return header_lines[0], header_lines[1:-1] if len(header_lines) > 2 else [], payload

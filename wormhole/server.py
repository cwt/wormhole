import asyncio
import functools
import socket
import sys
from time import time
from authentication import get_ident, verify
from handler import process_http, process_https, process_request
from logger import Logger


MAX_RETRY: int = 3

if sys.platform == "win32":
    import win32file

    MAX_TASKS: int = int(0.9 * win32file._getmaxstdio())
else:
    import resource

    MAX_TASKS: int = int(0.9 * resource.getrlimit(resource.RLIMIT_NOFILE)[0])

CURRENT_TASKS = 0


async def process_wormhole(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    auth: str | None,
) -> None:
    global CURRENT_TASKS
    logger = Logger().get_logger()
    ident = get_ident(client_reader, client_writer)

    request_line, headers, payload = await process_request(
        client_reader, MAX_RETRY, ident
    )
    if not request_line:

        logger.debug(
            f"[{ident['id']}][{ident['client']}]: !!! Task reject (empty request)"
        )
        return

    request_fields = request_line.split(" ")
    match len(request_fields):
        case 2:
            request_method, uri = request_fields
            http_version = "HTTP/1.0"
        case 3:
            request_method, uri, http_version = request_fields
        case _:
            logger.debug(
                f"[{ident['id']}][{ident['client']}]: !!! Task reject (invalid request)"
            )
            return

    if auth:
        user_ident = await verify(client_reader, client_writer, headers, auth)

        if user_ident is None:
            logger.info(
                f"[{ident['id']}][{ident['client']}]: {request_method} 407 {uri}"
            )
            return
        ident = user_ident

    CURRENT_TASKS += 1
    logger.debug(
        f"[{ident['id']}][{ident['client']}]: {CURRENT_TASKS}/{MAX_TASKS} Tasks active"
    )
    try:
        async with asyncio.TaskGroup() as tg:
            if request_method == "CONNECT":
                tg.create_task(
                    process_https(
                        client_reader, client_writer, request_method, uri, ident
                    )
                )
            else:
                tg.create_task(
                    process_http(
                        client_writer,
                        request_method,
                        uri,
                        http_version,
                        headers,
                        payload,
                        ident,
                    )
                )
    finally:
        CURRENT_TASKS -= 1


async def accept_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    auth: str | None,
) -> None:
    logger = Logger().get_logger()

    ident = get_ident(client_reader, client_writer)
    started_time = time()

    async def client_task() -> None:
        await process_wormhole(client_reader, client_writer, auth)
        client_writer.close()
        logger.debug(
            f"[{ident['id']}][{ident['client']}]: Connection closed ({time() - started_time:.5f} seconds)"
        )

    logger.debug(f"[{ident['id']}][{ident['client']}]: Connection started")
    await client_task()


async def start_wormhole_server(
    host: str, port: int, auth: str | None
) -> asyncio.Server:
    logger = Logger().get_logger()
    try:
        accept = functools.partial(accept_client, auth=auth)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        server = await asyncio.start_server(
            accept, host, port, family=family, limit=MAX_TASKS
        )
    except OSError as ex:
        logger.critical(
            f"[000000][{host}]: !!! Failed to bind server at [{host}:{port}]: {ex.args[1]}"
        )

        raise

    else:
        logger.info(f"[000000][{host}]: wormhole bound at {host}:{port}")
        return server

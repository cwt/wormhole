import asyncio
import functools
import socket
import sys
from time import time
from authentication import get_ident
from authentication import verify
from handler import process_http
from handler import process_https
from handler import process_request
from logger import Logger

MAX_RETRY = 3
if sys.platform == "win32":
    import win32file

    FREE_TASKS = asyncio.Semaphore(
        int(0.9 * win32file._getmaxstdio()))
else:
    import resource

    FREE_TASKS = asyncio.Semaphore(
        int(0.9 * resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    )
MAX_TASKS = FREE_TASKS._value

clients = dict()


async def process_wormhole(client_reader, client_writer, auth):
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
    if len(request_fields) == 2:
        request_method, uri = request_fields
        http_version = "HTTP/1.0"
    elif len(request_fields) == 3:
        request_method, uri, http_version = request_fields
    else:
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

    if request_method == "CONNECT":
        async with FREE_TASKS:
            logger.debug(
                f"[{ident['id']}][{ident['client']}]: {FREE_TASKS._value}/{MAX_TASKS} Resource available"
            )
            return await process_https(
                client_reader, client_writer, request_method, uri, ident
            )
    else:
        async with FREE_TASKS:
            logger.debug(
                f"[{ident['id']}][{ident['client']}]: {FREE_TASKS._value}/{MAX_TASKS} Resource available"
            )
            return await process_http(
                client_writer, request_method, uri, http_version, headers, payload, ident,
            )


async def accept_client(client_reader, client_writer, auth):
    logger = Logger().get_logger()
    ident = get_ident(client_reader, client_writer)
    task = asyncio.ensure_future(
        process_wormhole(client_reader, client_writer, auth)
    )
    global clients
    clients[task] = (client_reader, client_writer)
    started_time = time()

    def client_done(task):
        del clients[task]
        client_writer.close()
        logger.debug(
            f"[{ident['id']}][{ident['client']}]: Connection closed ({time() - started_time:.5f} seconds)"
        )

    logger.debug(f"[{ident['id']}][{ident['client']}]: Connection started")
    task.add_done_callback(client_done)


async def start_wormhole_server(host, port, auth):
    logger = Logger().get_logger()
    try:
        accept = functools.partial(accept_client, auth=auth)
        # Check if the host string contains an IPv6 address
        is_ipv6 = ":" in host
        if is_ipv6:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
        server = await asyncio.start_server(accept, host, port, family=family)
    except OSError as ex:
        logger.critical(
            f"[000000][{host}]: !!! Failed to bind server at [{host}:{port}]: {ex.args[1]}"
        )
        raise
    else:
        logger.info(f"[000000][{host}]: wormhole bound at {host}:{port}")
        return server

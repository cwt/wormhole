import asyncio
import functools
import sys
from time import time
from authentication import get_ident
from authentication import verify
from handler import process_http
from handler import process_https
from handler import process_request
from logger import get_logger


MAX_RETRY = 3
if sys.platform == "win32":
    import win32file

    MAX_TASKS = win32file._getmaxstdio()
else:
    import resource

    MAX_TASKS = resource.getrlimit(resource.RLIMIT_NOFILE)[0]


wormhole_semaphore = None


def get_wormhole_semaphore():
    max_wormholes = int(0.9 * MAX_TASKS)  # Use only 90% of open files limit.
    global wormhole_semaphore
    if wormhole_semaphore is None:
        wormhole_semaphore = asyncio.Semaphore(max_wormholes)
    return wormhole_semaphore


def debug_wormhole_semaphore(client_reader, client_writer):
    global wormhole_semaphore
    ident = get_ident(client_reader, client_writer)
    available = wormhole_semaphore._value
    logger = get_logger()
    logger.debug(
        f"[{ident['id']}][{ident['client']}]: "
        "Resource available: "
        f"{100 * available / MAX_TASKS:.2f}% ({available}/{MAX_TASKS})"
    )


async def process_wormhole(client_reader, client_writer, auth):
    logger = get_logger()
    ident = get_ident(client_reader, client_writer)

    request_line, headers, payload = await process_request(
        client_reader, MAX_RETRY, ident
    )
    if not request_line:
        logger.debug(
            f"[{ident['id']}][{ident['client']}]: "
            "!!! Task reject (empty request)"
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
            f"[{ident['id']}][{ident['client']}]: "
            "!!! Task reject (invalid request)"
        )
        return

    if auth:
        user_ident = await verify(client_reader, client_writer, headers, auth)
        if user_ident is None:
            logger.info(
                f"[{ident['id']}][{ident['client']}]: "
                f"{request_method} 407 {uri}"
            )
            return
        ident = user_ident

    if request_method == "CONNECT":
        async with get_wormhole_semaphore():
            debug_wormhole_semaphore(client_reader, client_writer)
            return await process_https(
                client_reader, client_writer, request_method, uri, ident
            )
    else:
        async with get_wormhole_semaphore():
            debug_wormhole_semaphore(client_reader, client_writer)
            return await process_http(
                client_writer,
                request_method,
                uri,
                http_version,
                headers,
                payload,
                ident,
            )


async def limit_wormhole(client_reader, client_writer, auth):
    async with get_wormhole_semaphore():
        debug_wormhole_semaphore(client_reader, client_writer)
        await process_wormhole(client_reader, client_writer, auth)
        debug_wormhole_semaphore(client_reader, client_writer)


clients = dict()


def accept_client(client_reader, client_writer, auth):
    logger = get_logger()
    ident = get_ident(client_reader, client_writer)
    task = asyncio.ensure_future(
        limit_wormhole(client_reader, client_writer, auth)
    )
    global clients
    clients[task] = (client_reader, client_writer)
    started_time = time()

    def client_done(task):
        del clients[task]
        client_writer.close()
        logger.debug(
            f"[{ident['id']}][{ident['client']}]: "
            f"Connection closed ({time() - started_time:.5f} seconds)"
        )

    logger.debug(f"[{ident['id']}][{ident['client']}]: Connection started")
    task.add_done_callback(client_done)


async def start_wormhole_server(host, port, auth):
    logger = get_logger()
    try:
        accept = functools.partial(accept_client, auth=auth)
        server = await asyncio.start_server(accept, host, port)
    except OSError as ex:
        logger.critical(
            f"[000000][{host}]: "
            f"!!! Failed to bind server at [{host}:{port}]: {ex.args[1]}"
        )
        raise
    else:
        logger.info(f"[000000][{host}]: wormhole bound at {host}:{port}")
        return server

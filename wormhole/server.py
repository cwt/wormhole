import asyncio
import functools
import resource
from time import time
from wormhole.authentication import get_ident
from wormhole.authentication import verify
from wormhole.handler import process_http
from wormhole.handler import process_https
from wormhole.handler import process_request
from wormhole.logger import get_logger


MAX_RETRY = 3
MAX_TASKS = resource.getrlimit(resource.RLIMIT_NOFILE)[0]


wormhole_semaphore = None
def get_wormhole_semaphore(loop):
    max_wormholes = int(0.9 * MAX_TASKS)  # Use only 90% of open files limit.
    global wormhole_semaphore
    if wormhole_semaphore is None:
        wormhole_semaphore = asyncio.Semaphore(max_wormholes, loop=loop)
    return wormhole_semaphore


def debug_wormhole_semaphore(client_reader, client_writer):
    global wormhole_semaphore
    ident = get_ident(client_reader, client_writer)
    available = wormhole_semaphore._value
    logger = get_logger()
    logger.debug((
        '[{id}][{client}]: Resource available: %.2f%% (%d/%d)' % (
            100 * float(available) / MAX_TASKS,
            available,
            MAX_TASKS
    )).format(**ident))


async def process_wormhole(client_reader, client_writer, cloaking, auth, loop):
    logger = get_logger()
    ident = get_ident(client_reader, client_writer)

    request_line, headers, payload = await process_request(
        client_reader, MAX_RETRY, ident, loop
    )
    if not request_line:
        logger.debug((
            '[{id}][{client}]: !!! Task reject (empty request)'
        ).format(**ident))
        return

    request_fields = request_line.split(' ')
    if len(request_fields) == 2:
        request_method, uri = request_fields
        http_version = 'HTTP/1.0'
    elif len(request_fields) == 3:
        request_method, uri, http_version = request_fields
    else:
        logger.debug((
            '[{id}][{client}]: !!! Task reject (invalid request)'
        ).format(**ident))
        return

    if auth:
        user_ident = await verify(client_reader, client_writer, headers, auth)
        if user_ident is None:
            logger.info((
                '[{id}][{client}]: %s 407 %s' % (request_method, uri)
            ).format(**ident))
            return
        ident = user_ident

    if request_method == 'CONNECT':
        async with get_wormhole_semaphore(loop=loop):
            debug_wormhole_semaphore(client_reader, client_writer)
            return await process_https(
                client_reader, client_writer, request_method, uri,
                ident, loop
            )
    else:
        async with get_wormhole_semaphore(loop=loop):
            debug_wormhole_semaphore(client_reader, client_writer)
            return await process_http(
                client_writer, request_method, uri, http_version,
                headers, payload, cloaking,
                ident, loop
            )


async def limit_wormhole(client_reader, client_writer, cloaking, auth, loop):
    async with get_wormhole_semaphore(loop=loop):
        debug_wormhole_semaphore(client_reader, client_writer)
        await process_wormhole(
            client_reader, client_writer, cloaking, auth, loop
        )
        debug_wormhole_semaphore(client_reader, client_writer)


clients = dict()
def accept_client(client_reader, client_writer, cloaking, auth, loop):
    logger = get_logger()
    ident = get_ident(client_reader, client_writer)
    task = asyncio.ensure_future(
        limit_wormhole(client_reader, client_writer, cloaking, auth, loop),
        loop=loop
    )
    global clients
    clients[task] = (client_reader, client_writer)
    started_time = time()

    def client_done(task):
        del clients[task]
        client_writer.close()
        logger.debug((
            '[{id}][{client}]: Connection closed (%.5f seconds)' % (
                time() - started_time
            )
        ).format(**ident))

    logger.debug((
        '[{id}][{client}]: Connection started'
    ).format(**ident))
    task.add_done_callback(client_done)


async def start_wormhole_server(host, port, cloaking, auth, loop):
    logger = get_logger()
    try:
        accept = functools.partial(
            accept_client, cloaking=cloaking, auth=auth, loop=loop
        )
        server = await asyncio.start_server(accept, host, port, loop=loop)
    except OSError as ex:
        logger.critical(
            '[000000][%s]: !!! Failed to bind server at [%s:%d]: %s' % (
                host, host, port, ex.args[1]
            )
        )
        raise
    else:
        logger.info(
            '[000000][%s]: wormhole bound at %s:%d' % (host, host, port)
        )
        return server

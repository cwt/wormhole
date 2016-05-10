import asyncio
from socket import TCP_NODELAY
from wormhole.cloaking import cloak
from wormhole.logger import get_logger
from wormhole.tools import get_content_length
from wormhole.tools import get_host_and_port


async def relay_stream(stream_reader, stream_writer,
                       ident, return_first_line=False):
    logger = get_logger()
    first_line = None
    while True:
        try:
            line = await stream_reader.read(1024)
            if len(line) == 0:
                break
            stream_writer.write(line)
        except Exception as ex:
            error_message = '%s: %s' % (
                ex.__class__.__name__,
                ' '.join([str(arg) for arg in ex.args])
            )
            logger.debug((
                '[{id}][{client}]: %s' % error_message
            ).format(**ident))
            break
        else:
            if return_first_line and first_line is None:
                first_line = line[:line.find(b'\r\n')]
    return first_line


async def process_https(client_reader, client_writer, request_method, uri,
                        ident, loop):
    response_code = 200
    error_message = None
    host, port = get_host_and_port(uri)
    logger = get_logger()
    try:
        req_reader, req_writer = await asyncio.open_connection(
            host, port, ssl=False, loop=loop
        )
        client_writer.write(b'HTTP/1.1 200 Connection established\r\n')
        client_writer.write(b'\r\n')
        # HTTPS need to log here, as the connection may keep alive for long.
        logger.info((
            '[{id}][{client}]: %s %d %s' % (
                request_method, response_code, uri
            )
        ).format(**ident))

        tasks = [
            asyncio.ensure_future(
                relay_stream(client_reader, req_writer, ident), loop=loop),
            asyncio.ensure_future(
                relay_stream(req_reader, client_writer, ident), loop=loop),
        ]
        await asyncio.wait(tasks, loop=loop)
    except Exception as ex:
        response_code = 502
        error_message = '%s: %s' % (
            ex.__class__.__name__,
            ' '.join([str(arg) for arg in ex.args])
        )
    if error_message:
        logger.error((
            '[{id}][{client}]: %s %d %s (%s)' % (
                request_method, response_code, uri, error_message
            )
        ).format(**ident))


async def process_http(client_writer, request_method, uri, http_version,
                       headers, payload, cloaking, ident, loop):
    response_status = None
    response_code = None
    error_message = None
    hostname = '127.0.0.1'  # hostname (with optional port) e.g. example.com:80
    request_headers = []
    request_headers_end_index = 0
    has_connection_header = False

    for header in headers:
        name_and_value = header.split(': ', 1)

        if len(name_and_value) == 2:
            name, value = name_and_value
        else:
            name, value = name_and_value[0], None

        if name.lower() == "host":
            if value is not None:
                hostname = value
        elif name.lower() == "connection":
            has_connection_header = True
            if value.lower() in ('keep-alive', 'persist'):
                # current version of this program does not support
                # the HTTP keep-alive feature
                request_headers.append("Connection: close")
            else:
                request_headers.append(header)
        elif name.lower() != 'proxy-connection':
            request_headers.append(header)
            if len(header) == 0 and request_headers_end_index == 0:
                request_headers_end_index = len(request_headers) - 1

    if request_headers_end_index == 0:
        request_headers_end_index = len(request_headers)

    if not has_connection_header:
        request_headers.insert(request_headers_end_index, "Connection: close")

    path = uri[len(hostname) + 7:]  # 7 is len('http://')
    new_head = ' '.join([request_method, path, http_version])

    host, port = get_host_and_port(hostname, 80)

    try:
        req_reader, req_writer = await asyncio.open_connection(
            host, port, flags=TCP_NODELAY, loop=loop
        )
        req_writer.write(('%s\r\n' % new_head).encode())
        await req_writer.drain()

        if cloaking:
            await cloak(req_writer, hostname, loop)
        else:
            req_writer.write(b'Host: ' + hostname.encode())
        req_writer.write(b'\r\n')

        [req_writer.write((header + '\r\n').encode())
         for header in request_headers]
        req_writer.write(b'\r\n')

        if payload != b'':
            req_writer.write(payload)
            req_writer.write(b'\r\n')
        await req_writer.drain()

        response_status = await relay_stream(
            req_reader, client_writer, ident, True
        )
    except Exception as ex:
        response_code = 502
        error_message = '%s: %s' % (
            ex.__class__.__name__,
            ' '.join([str(arg) for arg in ex.args])
        )

    if response_code is None:
        response_code = int(response_status.decode('ascii').split(' ')[1])
    logger = get_logger()
    if error_message is None:
        logger.info((
            '[{id}][{client}]: %s %d %s' % (
                request_method, response_code, uri
            )
        ).format(**ident))
    else:
        logger.error((
            '[{id}][{client}]: %s %d %s (%s)' % (
                request_method, response_code, uri, error_message
            )
        ).format(**ident))


async def process_request(client_reader, max_retry, ident, loop):
    logger = get_logger()
    request_line = ''
    headers = []
    header = ''
    payload = b''
    try:
        retry = 0
        while True:
            line = await client_reader.readline()
            if not line:
                if len(header) == 0 and retry < max_retry:
                    # handle the case when the client make connection
                    # but sending data is delayed for some reasons
                    retry += 1
                    await asyncio.sleep(0.1, loop=loop)
                    continue
                else:
                    break
            if line == b'\r\n':
                break
            if line != b'':
                header += line.decode()

        content_length = get_content_length(header)
        while len(payload) < content_length:
            payload += await client_reader.read(1024)
    except Exception as ex:
        logger.debug((
            '[{id}][{client}]: !!! Task reject (%s: %s)' % (
                ex.__class__.__name__,
                ' '.join([str(arg) for arg in ex.args])
            )
        ).format(**ident))

    if header:
        header_lines = header.split('\r\n')
        if len(header_lines) > 1:
            request_line = header_lines[0]
        if len(header_lines) > 2:
            headers = header_lines[1:-1]

    return request_line, headers, payload

"""
Copyright (c) 2016 cwt
Copyright (c) 2013 devunt

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

import asyncio
import logging
import functools
import re
from socket import TCP_NODELAY
from time import time
from wormhole.authentication import verify
from wormhole.cloaking import cloak


REGEX_HOST = re.compile(r'(.+?):([0-9]{1,5})')
REGEX_CONTENT_LENGTH = re.compile(r'\r\nContent-Length: ([0-9]+)\r\n',
                                  re.IGNORECASE)
REGEX_CONNECTION = re.compile(r'\r\nConnection: (.+)\r\n', re.IGNORECASE)

logging.basicConfig(level=logging.INFO,
                    format=('%(asctime)s %(name)s[%(process)d]: %(message)s'))
logger = logging.getLogger('wormhole')

clients = {}


async def process_request(client_reader, ident, loop):
    request_line = ''
    header_fields = []
    header = ''
    payload = b''
    try:
        RECV_MAX_RETRY = 3
        recvRetry = 0
        while True:
            line = await client_reader.readline()
            if not line:
                if len(header) == 0 and recvRetry < RECV_MAX_RETRY:
                    # handle the case when the client make connection but
                    # sending data is delayed for some reasons
                    recvRetry += 1
                    await asyncio.sleep(0.1, loop=loop)
                    continue
                else:
                    break
            if line == b'\r\n':
                break
            if line != b'':
                header += line.decode()
        m = REGEX_CONTENT_LENGTH.search(header)
        if m:
            cl = int(m.group(1))
            while (len(payload) < cl):
                payload += await client_reader.read(1024)
    except Exception as e:
        logger.debug('!!! Task reject (%s)' % e, extra=ident)

    if header:
        headers = header.split('\r\n')
        if len(headers) > 1:
            request_line = headers[0]
        if len(headers) > 2:
            header_fields = headers[1:-1]

    return request_line, header_fields, payload


async def process_https(client_reader, client_writer,
                        request_method, uri, ident, loop):
    m = REGEX_HOST.search(uri)
    host = m.group(1)
    port = int(m.group(2))
    if port == 443:
        url = 'https://%s/' % host
    else:
        url = 'https://%s:%s/' % (host, port)
    try:
        logger.info((
            '[{id}][{client}]: %s 200 %s' % (request_method, url)
        ).format(**ident))
        req_reader, req_writer = await asyncio.open_connection(
            host, port, ssl=False, loop=loop
        )
        client_writer.write(b'HTTP/1.1 200 Connection established\r\n')
        client_writer.write(b'\r\n')

        async def relay_stream(reader, writer):
            try:
                while True:
                    line = await reader.read(1024)
                    if len(line) == 0:
                        break
                    writer.write(line)
            except:
                logger.info((
                    '[{id}][{client}]: %s 502 %s' % (request_method, url)
                ).format(**ident))

        tasks = [
            asyncio.ensure_future(
                relay_stream(client_reader, req_writer), loop=loop),
            asyncio.ensure_future(
                relay_stream(req_reader, client_writer), loop=loop),
        ]
        await asyncio.wait(tasks, loop=loop)
    except:
        logger.info((
            '[{id}][{client}]: %s 502 %s' % (request_method, url)
        ).format(**ident))


async def process_http(client_reader, client_writer,
                       request_method, uri, http_version,
                       header_fields, payload, cloaking, ident, loop):
    phost = False
    sreq = []
    sreqHeaderEndIndex = 0
    has_connection_header = False

    for header in header_fields:
        headerNameAndValue = header.split(': ', 1)

        if len(headerNameAndValue) == 2:
            headerName, headerValue = headerNameAndValue
        else:
            headerName, headerValue = headerNameAndValue[0], None

        if headerName.lower() == "host":
            phost = headerValue
        elif headerName.lower() == "connection":
            has_connection_header = True
            if headerValue.lower() in ('keep-alive', 'persist'):
                # current version of this program does not support the HTTP
                # keep-alive feature
                sreq.append("Connection: close")
            else:
                sreq.append(header)
        elif headerName.lower() != 'proxy-connection':
            sreq.append(header)
            if len(header) == 0 and sreqHeaderEndIndex == 0:
                sreqHeaderEndIndex = len(sreq) - 1

    if sreqHeaderEndIndex == 0:
        sreqHeaderEndIndex = len(sreq)

    if not has_connection_header:
        sreq.insert(sreqHeaderEndIndex, "Connection: close")

    if not phost:
        phost = '127.0.0.1'

    path = uri[len(phost) + 7:]  # 7 is len('http://')
    new_head = ' '.join([request_method, path, http_version])

    m = REGEX_HOST.search(phost)
    if m:
        host = m.group(1)
        port = int(m.group(2))
    else:
        host = phost
        port = 80

    response_status = None
    response_code = None
    try:
        req_reader, req_writer = await asyncio.open_connection(
            host, port, flags=TCP_NODELAY, loop=loop
        )
        req_writer.write(('%s\r\n' % new_head).encode())
        await req_writer.drain()
        await asyncio.sleep(0.01, loop=loop)

        if cloaking:
            await cloak(req_writer, phost, loop)
        else:
            req_writer.write(b'Host: ' + phost.encode())
        req_writer.write(b'\r\n')

        [req_writer.write((header+'\r\n').encode()) for header in sreq]
        req_writer.write(b'\r\n')

        if payload != b'':
            req_writer.write(payload)
            req_writer.write(b'\r\n')
        await req_writer.drain()

        try:
            while True:
                buf = await req_reader.read(1024)
                if response_status is None:
                    response_status = buf[:buf.find(b'\r\n')]
                if len(buf) == 0:
                    break
                client_writer.write(buf)
        except:
            response_code = '502'
    except:
        response_code = '502'

    if response_code is None:
        response_code = response_status.decode('ascii').split(' ')[1]
    logger.info((
        '[{id}][{client}]: %s %s %s' % (request_method, response_code, uri)
    ).format(**ident))


async def process_wormhole(client_reader, client_writer, cloaking, auth, loop):
    ident = {'id': hex(id(client_reader))[-6:],
             'client': client_writer.get_extra_info('peername')[0]}

    request_line, header_fields, payload = await process_request(
        client_reader, ident, loop
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
        verified_ident = await verify(
            client_writer, request_method, uri,
            header_fields, auth, ident
        )
        if verified_ident is None:
            if request_method == 'CONNECT':
                host, port = uri.split(':')
                if port == '443':
                    url = 'https://%s/' % host
                else:
                    url = 'https://%s:%s/' % (host, port)
            else:
                url = uri
            logger.info((
                '[{id}][{client}]: %s 407 %s' % (request_method, url)
            ).format(**ident))
            return
        ident = verified_ident

    if request_method == 'CONNECT':  # https proxy
        return await process_https(
            client_reader, client_writer, request_method, uri,
            ident, loop
        )
    else:
        return await process_http(
            client_reader, client_writer, request_method, uri, http_version,
            header_fields, payload, cloaking,
            ident, loop
        )


def accept_client(client_reader, client_writer, cloaking, auth, loop):
    ident = {'id': hex(id(client_reader))[-6:],
             'client': client_writer.get_extra_info('peername')[0]}
    task = asyncio.ensure_future(
        process_wormhole(client_reader, client_writer, cloaking, auth, loop),
        loop=loop
    )
    clients[task] = (client_reader, client_writer)
    started_time = time()

    def client_done(task):
        try:
            del clients[task]
        except:
            pass
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


async def start_wormhole_server(host, port, cloaking, auth, verbose, loop):
    ident = {'id': '', 'client': ''}
    if verbose > 0:
        logging.getLogger('wormhole').setLevel(logging.DEBUG)
    try:
        accept = functools.partial(
            accept_client, cloaking=cloaking, auth=auth, loop=loop
        )
        server = await asyncio.start_server(accept, host, port, loop=loop)
    except OSError as ex:
        logger.critical((
            '[{id}][{client}]: !!! Failed to bind server at [%s:%d]: %s' % (
                host, port, ex.args[1]
            )
        ).format(**ident))
        raise
    else:
        logger.info((
            '[{id}][{client}]: wormhole bound at %s:%d.' % (host, port)
        ).format(**ident))
        return server


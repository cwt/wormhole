#!/usr/bin/env python3
from pip._vendor.requests.auth import HTTPProxyAuth

VERSION = "v0.2.0-py35"

"""
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

import sys
if sys.version_info < (3, 5):
    print('Error: You need python 3.5.0 or above.')
    exit(1)

from argparse import ArgumentParser
from string import ascii_letters, ascii_uppercase, digits
from socket import TCP_NODELAY
from time import time
import asyncio
import base64
import logging
import random
import functools
import re


REGEX_HOST           = re.compile(r'(.+?):([0-9]{1,5})')
REGEX_CONTENT_LENGTH = re.compile(r'\r\nContent-Length: ([0-9]+)\r\n', re.IGNORECASE)
REGEX_CONNECTION     = re.compile(r'\r\nConnection: (.+)\r\n', re.IGNORECASE)

clients = {}

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s')
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logger = logging.getLogger('warp')
verbose = 0


def generate_dummyheaders():
    def generate_rndstrs(strings, length):
        return ''.join(random.choice(strings) for _ in range(length))
    return ['X-%s: %s\r\n' % (generate_rndstrs(ascii_uppercase, 16),
        generate_rndstrs(ascii_letters + digits, 128)) for _ in range(32)]


def accept_client(client_reader, client_writer, cloak, auth, *, loop=None):
    ident = '%s %s' % (hex(id(client_reader))[-6:],
                       client_writer.get_extra_info('peername')[0])
    task = asyncio.ensure_future(process_warp(client_reader, client_writer, cloak, auth, loop=loop), loop=loop)
    clients[task] = (client_reader, client_writer)
    started_time = time()

    def client_done(task):
        del clients[task]
        client_writer.close()
        logger.debug('[%s] Connection closed (took %.5f seconds)' % (ident, time() - started_time))

    logger.debug('[%s] Connection started' % ident)
    task.add_done_callback(client_done)

async def process_request(client_reader, ident, loop):
    header = ''
    payload = b''

    try:
        RECV_MAX_RETRY = 3
        recvRetry = 0
        while True:
            line = await client_reader.readline()
            if not line:
                if len(header) == 0 and recvRetry < RECV_MAX_RETRY:
                    # handle the case when the client make connection but sending data is delayed for some reasons
                    recvRetry += 1
                    await asyncio.sleep(0.2, loop=loop)
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
        logger.debug('%s !!! Task reject (%s)' % (ident, e))

    return header, payload


async def process_ssl(client_reader, client_writer, head, ident, loop):
    m = REGEX_HOST.search(head[1])
    host = m.group(1)
    port = int(m.group(2))
    if port == 443:
        url = 'https://%s/' % host
    else:
        url = 'https://%s:%s/' % (host, port)
    try:
        logger.info('%s %s 200 %s' % (ident, head[0], url))
        req_reader, req_writer = await asyncio.open_connection(host, port, ssl=False, loop=loop)
        client_writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
        async def relay_stream(reader, writer):
            try:
                while True:
                    line = await reader.read(1024)
                    if len(line) == 0:
                        break
                    writer.write(line)
            except:
                logger.info('%s %s 502 %s' % (ident, head[0], url))
        tasks = [
            asyncio.ensure_future(relay_stream(client_reader, req_writer), loop=loop),
            asyncio.ensure_future(relay_stream(req_reader, client_writer), loop=loop),
        ]
        await asyncio.wait(tasks, loop=loop)
    except:
        logger.info('%s %s 502 %s' % (ident, head[0], url))


def auth_denied(client_writer, head, ident):
    client_writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n')
    client_writer.write(b'Proxy-Authenticate: Basic realm="Warp Proxy"\r\n')
    if head[0] == 'CONNECT':
        host, port = head[1].split(':')
        if port == '443':
            url = 'https://%s/' % host
        else:
            url = 'https://%s:%s/' % (host, port)
    else:
        url = head[1]
    logger.info('%s %s 407 %s' % (ident, head[0], url))
    raise Exception('HTTP/1.1 407 Proxy Authentication Required')


AUTH_LIST = None
async def check_auth(client_writer, head, ident, auth, req):
    proxy_auth = [req_line for req_line in req
                  if req_line.lower().startswith('proxy-authorization:')]
    if len(proxy_auth) == 0:
        return auth_denied(client_writer, head, ident)
    else:
        global AUTH_LIST
        if AUTH_LIST is None:
            AUTH_LIST = [
                line.strip()
                for line in open('warp.passwd','r').readlines()
                if line.strip() and not line.strip().startswith('#')
            ]
        user_password = base64.decodebytes(
            proxy_auth[0].split(' ')[2].encode('ascii')
        ).decode('ascii')
        if user_password not in AUTH_LIST:
            return auth_denied(client_writer, head, ident)
        user = user_password.split(':')[0]
        return ident.replace(' ', ' %s@' % user)
 

async def process_warp(client_reader, client_writer, cloak, auth, *, loop=None):
    ident = '%s %s' % (hex(id(client_reader))[-6:],
                       client_writer.get_extra_info('peername')[0])

    header, payload = await process_request(client_reader, ident, loop)

    if len(header) == 0:
        logger.debug('%s !!! Task reject (empty request)' % ident)
        return

    req = header.split('\r\n')[:-1]
    if len(req) < 4:
        logger.debug('%s !!! Task reject (invalid request)' % ident)
        return

    head = req[0].split(' ')
    if auth:
        try:
            ident = await check_auth(client_writer, head, ident, auth, req)
        except:
            return
    if head[0] == 'CONNECT': # https proxy
        return await process_ssl(client_reader, client_writer, head, ident, loop)

    phost = False
    sreq = []
    sreqHeaderEndIndex = 0
    for line in req[1:]:
        headerNameAndValue = line.split(': ', 1)
        if len(headerNameAndValue) == 2:
            headerName, headerValue = headerNameAndValue
        else:
            headerName, headerValue = headerNameAndValue[0], None

        if headerName.lower() == "host":
            phost = headerValue
        elif headerName.lower() == "connection":
            if headerValue.lower() in ('keep-alive', 'persist'):
                # current version of this program does not support the HTTP keep-alive feature
                sreq.append("Connection: close")
            else:
                sreq.append(line)
        elif headerName.lower() != 'proxy-connection':
            sreq.append(line)
            if len(line) == 0 and sreqHeaderEndIndex == 0:
                sreqHeaderEndIndex = len(sreq) - 1
    if sreqHeaderEndIndex == 0:
        sreqHeaderEndIndex = len(sreq)

    m = REGEX_CONNECTION.search(header)
    if not m:
        sreq.insert(sreqHeaderEndIndex, "Connection: close")

    if not phost:
        phost = '127.0.0.1'
    path = head[1][len(phost)+7:]

    new_head = ' '.join([head[0], path, head[2]])

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
        req_reader, req_writer = await asyncio.open_connection(host, port, flags=TCP_NODELAY, loop=loop)
        req_writer.write(('%s\r\n' % new_head).encode())
        await req_writer.drain()
        await asyncio.sleep(0.2, loop=loop)

        if cloak:
            req_writer.writelines(list(map(lambda x: x.encode(), generate_dummyheaders())))
            await req_writer.drain()

        req_writer.write(b'Host: ')
        await req_writer.drain()
        def feed_phost(phost):
            i = 1
            while phost:
                yield random.randrange(2, 4), phost[:i]
                phost = phost[i:]
                i = random.randrange(2, 5)
        for delay, c in feed_phost(phost):
            await asyncio.sleep(delay / 10.0, loop=loop)
            req_writer.write(c.encode())
            await req_writer.drain()
        req_writer.write(b'\r\n')
        req_writer.writelines(list(map(lambda x: (x + '\r\n').encode(), sreq)))
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
    logger.info('%s %s %s %s' % (ident, head[0], response_code, head[1]))


async def start_warp_server(host, port, cloak, auth, *, loop = None):
    try:
        accept = functools.partial(accept_client, cloak=cloak, auth=auth, loop=loop)
        server = await asyncio.start_server(accept, host=host, port=port, loop=loop)
    except OSError as ex:
        logger.critical('!!! Failed to bind server at [%s:%d]: %s' % (host, port, ex.args[1]))
        raise
    else:
        logger.info('Server bound at [%s:%d].' % (host, port))
        return server


def main():
    """CLI frontend function.  It takes command line options e.g. host,
    port and provides `--help` message.

    """
    parser = ArgumentParser(description='Simple HTTP transparent proxy')
    parser.add_argument('-H', '--host', default='127.0.0.1',
        help='Host to listen [default: %(default)s]')
    parser.add_argument('-p', '--port', type=int, default=8800,
        help='Port to listen [default: %(default)d]')
    parser.add_argument('-a', '--auth', default='',
        help='File contains username and password list for proxy authentication [default: no auth]')
    parser.add_argument('-c', '--cloak', action='store_true', default=False,
        help='Add random string to header [default: %(default)s]')
    parser.add_argument('-v', '--verbose', action='count', default=0,
        help='Print verbose')
    args = parser.parse_args()
    if not (1 <= args.port <= 65535):
        parser.error('port must be 1-65535')
    if args.verbose >= 3:
        parser.error('verbose level must be 1-2')
    if args.verbose >= 1:
        logger.setLevel(logging.DEBUG)
    if args.verbose >= 2:
        logging.getLogger('warp').setLevel(logging.DEBUG)
        logging.getLogger('asyncio').setLevel(logging.DEBUG)
    global verbose
    verbose = args.verbose
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_warp_server(args.host, args.port, args.cloak, args.auth))
        loop.run_forever()
    except OSError:
        pass
    except KeyboardInterrupt:
        print('bye')
    finally:
        loop.close()


if __name__ == '__main__':
    exit(main())

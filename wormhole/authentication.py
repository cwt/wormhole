"""
Copyright (c) 2016 cwt

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

from base64 import decodebytes


AUTH_LIST = []


def get_auth_list(auth):
    global AUTH_LIST
    if not AUTH_LIST:
        AUTH_LIST = [
            line.strip()
            for line in open(auth, 'r')
            if line.strip() and not line.strip().startswith('#')
        ]
    return AUTH_LIST


def deny(client_writer):
    DENY_MESSAGES = [
        b'HTTP/1.1 407 Proxy Authentication Required\r\n',
        b'Proxy-Authenticate: Basic realm="Wormhole Proxy"\r\n',
        b'\r\n'
    ]
    [client_writer.write(message) for message in DENY_MESSAGES]


async def verify(client_writer, request_method, uri, headers, auth, ident):
    proxy_auth = [header for header in headers
                  if header.lower().startswith('proxy-authorization:')]
    if proxy_auth:
        user_password = decodebytes(
            proxy_auth[0].split(' ')[2].encode('ascii')
        ).decode('ascii')
        if user_password in get_auth_list(auth):
            user = user_password.split(':')[0]
            return {'id': ident['id'],
                    'client': '%s@%s' % (user, ident['client'])}
    return deny(client_writer)

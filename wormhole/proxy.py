#!/usr/bin/env python3

VERSION = "v1.4"

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

import sys
if sys.version_info < (3, 5):
    print('Error: You need python 3.5.0 or above.')
    exit(1)

import asyncio
from argparse import ArgumentParser
from wormhole.server import start_wormhole_server


def main():
    """CLI frontend function.  It takes command line options e.g. host,
    port and provides `--help` message.
    """
    parser = ArgumentParser(
        description='Wormhole(%s): Asynchronous IO HTTP and HTTPS Proxy' %
        VERSION)
    parser.add_argument(
        '-H', '--host', default='0.0.0.0',
        help='Host to listen [default: %(default)s]'
    )
    parser.add_argument(
        '-p', '--port', type=int, default=8800,
        help='Port to listen [default: %(default)d]'
    )
    parser.add_argument(
        '-a', '--authentication', default='',
        help=('File contains username and password list '
              'for proxy authentication [default: no authentication]')
    )
    parser.add_argument(
        '-c', '--cloaking', action='store_true', default=False,
        help='Add random string to header [default: %(default)s]'
    )
    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='Print verbose'
    )
    args = parser.parse_args()
    if not (1 <= args.port <= 65535):
        parser.error('port must be 1-65535')

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            start_wormhole_server(
                args.host, args.port,
                args.cloaking, args.authentication,
                args.verbose, loop
            )
        )
        loop.run_forever()
    except OSError:
        pass
    except KeyboardInterrupt:
        print('bye')
    finally:
        loop.close()


if __name__ == '__main__':
    exit(main())


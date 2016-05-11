#!/usr/bin/env python3

VERSION = "v2.0.1"

import sys
if sys.version_info < (3, 5):
    print('Error: You need python 3.5.0 or above.')
    exit(1)

import asyncio
from argparse import ArgumentParser
from wormhole.license import LICENSE
from wormhole.logger import get_logger
from wormhole.server import start_wormhole_server


def main():
    """CLI frontend function.  It takes command line options e.g. host,
    port and provides `--help` message.
    """
    parser = ArgumentParser(
        description='Wormhole(%s): Asynchronous IO HTTP and HTTPS Proxy' %
        VERSION
    )
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
        '-S', '--syslog-host', default='DISABLED',
        help='Syslog Host [default: %(default)s]'
    )
    parser.add_argument(
        '-P', '--syslog-port', type=int, default=514,
        help='Syslog Port to listen [default: %(default)d]'
    )
    parser.add_argument(
        '-l', '--license', action='store_true', default=False,
        help='Print LICENSE and exit'
    )
    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='Print verbose'
    )
    args = parser.parse_args()
    if args.license:
        print(parser.description)
        print(LICENSE)
        exit()
    if not (1 <= args.port <= 65535):
        parser.error('port must be 1-65535')

    logger = get_logger(args.syslog_host, args.syslog_port, args.verbose)
    try:
        import uvloop
    except ImportError:
        pass
    else:
        logger.debug(
            '[000000][%s]: Using event loop from uvloop.' % args.host
        )
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            start_wormhole_server(
                args.host, args.port,
                args.cloaking, args.authentication,
                loop
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

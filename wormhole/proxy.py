#!/usr/bin/env python3

import sys

if sys.version_info < (3, 5):
    print("Error: You need python 3.5.0 or above.")
    exit(1)

import os
from pathlib import Path

sys.path.insert(0, Path(os.path.realpath(__file__)).parent.as_posix())

import asyncio
from argparse import ArgumentParser
from license import LICENSE
from logger import get_logger
from server import start_wormhole_server
from version import VERSION


def main():
    """CLI frontend function.  It takes command line options e.g. host,
    port and provides `--help` message.
    """
    parser = ArgumentParser(
        description=(
            f"Wormhole({VERSION}): Asynchronous IO HTTP and HTTPS Proxy"
        )
    )
    parser.add_argument(
        "-H",
        "--host",
        default="0.0.0.0",
        help="Host to listen [default: %(default)s]",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8800,
        help="Port to listen [default: %(default)d]",
    )
    parser.add_argument(
        "-a",
        "--authentication",
        default="",
        help=(
            "File contains username and password list "
            "for proxy authentication [default: no authentication]"
        ),
    )
    parser.add_argument(
        "-S",
        "--syslog-host",
        default="DISABLED",
        help="Syslog Host [default: %(default)s]",
    )
    parser.add_argument(
        "-P",
        "--syslog-port",
        type=int,
        default=514,
        help="Syslog Port to listen [default: %(default)d]",
    )
    parser.add_argument(
        "-l",
        "--license",
        action="store_true",
        default=False,
        help="Print LICENSE and exit",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Print verbose"
    )
    args = parser.parse_args()
    if args.license:
        print(parser.description)
        print(LICENSE)
        exit()
    if not (1 <= args.port <= 65535):
        parser.error("port must be 1-65535")

    logger = get_logger(args.syslog_host, args.syslog_port, args.verbose)
    try:
        import uvloop
    except ImportError:
        pass
    else:
        logger.debug(f"[000000][{args.host}]: Using event loop from uvloop.")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            start_wormhole_server(
                args.host,
                args.port,
                args.authentication,
            )
        )
        loop.run_forever()
    except OSError:
        pass
    except KeyboardInterrupt:
        print("bye")
    finally:
        loop.close()


if __name__ == "__main__":
    exit(main())

#!/usr/bin/env python3

import sys
import signal

if sys.version_info < (3, 11):
    print("Error: You need Python 3.11 or newer.")
    sys.exit(1)

import asyncio
from argparse import ArgumentParser
from pathlib import Path

from license import LICENSE
from logger import Logger
from version import VERSION

sys.path.insert(0, str(Path(__file__).parent.resolve()))

try:
    if sys.platform in ("win32", "cygwin"):
        import winloop as uvloop
    else:
        import uvloop
except ImportError:
    uvloop = None


async def start_server(
    host: str, port: int, auth: str | None, shutdown_event: asyncio.Event
) -> None:
    from server import start_wormhole_server

    server = await start_wormhole_server(host, port, auth)
    await shutdown_event.wait()  # รอสัญญาณ shutdown
    server.close()
    await server.wait_closed()


def main() -> int:
    parser = ArgumentParser(
        description=f"Wormhole({VERSION}): Asynchronous IO HTTP and HTTPS Proxy"
    )
    parser.add_argument(
        "-H", "--host", default="0.0.0.0", help="Host to listen [default: %(default)s]"
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
        help="File contains username and password list [default: no auth]",
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
        help="Syslog Port [default: %(default)d]",
    )
    parser.add_argument(
        "-l", "--license", action="store_true", help="Print LICENSE and exit"
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Print verbose"
    )
    args = parser.parse_args()

    if args.license:
        print(parser.description)
        print(LICENSE)
        return 0

    if not 1 <= args.port <= 65535:
        parser.error("port must be 1-65535")

    logger = Logger(args.syslog_host, args.syslog_port, args.verbose).get_logger()
    if args.verbose:
        logger.debug(
            f"[000000][{args.host}]: Using {uvloop.__name__ if uvloop else 'default event loop'}"
        )

    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    # Signal handler
    def handle_shutdown(signum, frame):

        print("\nbye")
        shutdown_event.set()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)  # จับ SIGTERM ด้วย (เช่นจาก Docker)

    runner = uvloop.run if uvloop else asyncio.run
    runner(start_server(args.host, args.port, args.authentication, shutdown_event))
    return 0


if __name__ == "__main__":
    sys.exit(main())

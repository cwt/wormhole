#!/usr/bin/env python3

import sys

# Ensure the script is run with a compatible Python version.
if sys.version_info < (3, 11):
    print("Error: Wormhole requires Python 3.11 or newer.", file=sys.stderr)
    sys.exit(1)

from .logger import logger, setup_logger
from .server import start_wormhole_server
from .version import VERSION
from argparse import ArgumentParser
from pathlib import Path
from types import ModuleType
import asyncio
import signal

uvloop: ModuleType | None = None
try:
    if sys.platform == "win32":
        import winloop as uvloop
    else:
        import uvloop
except ImportError:
    pass  # uvloop or winloop is an optional for speedup, not a requirement


async def main_async(args) -> None:
    """The main asynchronous function to run the server."""
    setup_logger(args.syslog_host, args.syslog_port, args.verbose)

    if uvloop:
        logger.info(f"Using high-performance event loop: {uvloop.__name__}")
    else:
        logger.info("Using standard asyncio event loop.")

    shutdown_event = asyncio.Event()

    # Set up signal handlers for graceful shutdown.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: shutdown_event.set())

    server = await start_wormhole_server(
        args.host,
        args.port,
        args.authentication,
        args.verbose,
        args.allow_private,
    )

    logger.info("Server startup complete. Waiting for connections...")

    # Wait for the shutdown signal.
    await shutdown_event.wait()

    # Gracefully shut down the server.
    logger.info("Shutdown signal received, closing server...")
    server.close()
    await server.wait_closed()
    logger.info("Server has been shut down gracefully.")


def main() -> int:
    """Parses command-line arguments and starts the event loop."""
    parser = ArgumentParser(
        description=f"Wormhole ({VERSION}): Asynchronous I/O HTTP/S Proxy"
    )
    parser.add_argument(
        "-H",
        "--host",
        default="0.0.0.0",
        help="Host address to bind [default: %(default)s]",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8800,
        help="Port to listen on [default: %(default)d]",
    )
    parser.add_argument(
        "-a",
        "--authentication",
        default=None,
        help="Path to authentication file (user:pass list)",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow proxying to private and reserved IP addresses (disabled by default)",
    )
    parser.add_argument(
        "-S",
        "--syslog-host",
        default=None,
        help="Syslog host or path (e.g., /dev/log)",
    )
    parser.add_argument(
        "-P",
        "--syslog-port",
        type=int,
        default=514,
        help="Syslog port [default: %(default)d]",
    )
    parser.add_argument(
        "-l",
        "--license",
        action="store_true",
        help="Print license information and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv)",
    )
    args = parser.parse_args()

    if args.license:
        print(parser.description)
        try:
            # The LICENSE file is in the project root, one level above.
            license_path = Path(__file__).resolve().parent.parent / "LICENSE"
            print(license_path.read_text())
        except FileNotFoundError:
            print("\nError: LICENSE file not found.", file=sys.stderr)
            return 1
        return 0

    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535.")

    if args.authentication and not Path(args.authentication).is_file():
        parser.error(f"Authentication file not found: {args.authentication}")

    if uvloop:
        uvloop.install()

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
    except Exception as e:
        # Catch-all for critical startup errors, like binding failure.
        print(f"A critical error occurred: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

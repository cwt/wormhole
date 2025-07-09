#!/usr/bin/env python3

import sys

# Ensure the script is run with a compatible Python version.
if sys.version_info < (3, 11):
    print("Error: Wormhole requires Python 3.11 or newer.", file=sys.stderr)
    sys.exit(1)

from .ad_blocker import update_database
from .auth_manager import add_user, modify_user, delete_user
from .logger import logger, setup_logger
from .safeguards import load_ad_block_db, load_allowlist
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
    if uvloop:
        logger.info(f"Using high-performance event loop: {uvloop.__name__}")
    else:
        logger.info("Using standard asyncio event loop.")

    if args.allowlist:
        num_allowed = load_allowlist(args.allowlist)
        if num_allowed > 0:
            logger.info(
                f"Loaded custom allowlist. Total allowlist size: {num_allowed} domains."
            )

    if args.ad_block_db:
        num_blocked = await load_ad_block_db(args.ad_block_db)
        if num_blocked > 0:
            logger.info(
                f"Ad-blocker enabled with {num_blocked} domains from database."
            )

    shutdown_event = asyncio.Event()

    # Set up signal handlers for graceful shutdown.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: shutdown_event.set())

    server = await start_wormhole_server(
        args.host,
        args.port,
        args.auth,
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
    # Authentication arguments
    auth_group = parser.add_argument_group("Authentication Options")
    auth_group.add_argument(
        "--auth",
        metavar="AUTH_FILE",
        default=None,
        help="Enable Digest authentication using the specified file.",
    )
    auth_group.add_argument(
        "--auth-add",
        nargs=2,
        metavar=("<AUTH_FILE>", "<USERNAME>"),
        help="Add a user to the authentication file and exit.",
    )
    auth_group.add_argument(
        "--auth-mod",
        nargs=2,
        metavar=("<AUTH_FILE>", "<USERNAME>"),
        help="Modify a user's password in the authentication file and exit.",
    )
    auth_group.add_argument(
        "--auth-del",
        nargs=2,
        metavar=("<AUTH_FILE>", "<USERNAME>"),
        help="Delete a user from the authentication file and exit.",
    )
    # Ad-block arguments
    ad_block_group = parser.add_argument_group("Ad-Blocker Options")
    ad_block_group.add_argument(
        "--ad-block-db",
        default=None,
        help="Path to the SQLite database file containing domains to block.",
    )
    ad_block_group.add_argument(
        "--update-ad-block-db",
        metavar="DB_PATH",
        default=None,
        help="Fetch public ad-block lists and compile them into a database file, then exit.",
    )
    ad_block_group.add_argument(
        "--allowlist",
        default=None,
        help="Path to a file of domains to extend the default allowlist.",
    )
    args = parser.parse_args()

    # Print license information and exit.
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

    # Handle authentication management commands.
    if args.auth_add:
        return add_user(args.auth_add[0], args.auth_add[1])
    if args.auth_mod:
        return modify_user(args.auth_mod[0], args.auth_mod[1])
    if args.auth_del:
        return delete_user(args.auth_del[0], args.auth_del[1])

    # Setup the uvloop before any other operations thay migh use the event loop.
    if uvloop:
        uvloop.install()

    # Setup logging before any other operations.
    setup_logger(args.syslog_host, args.syslog_port, args.verbose)

    if args.update_ad_block_db:
        # For this standalone utility, configure a simple logger to show progress.
        logger.info(f"Updating ad-block database at: {args.update_ad_block_db}")
        try:
            asyncio.run(
                update_database(args.update_ad_block_db, args.allowlist)
            )
        except Exception as e:
            logger.error(f"\nAn error occurred during update: {e}")
            return 1
        return 0

    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535.")

    if args.auth and not Path(args.auth).is_file():
        parser.error(f"Authentication file not found: {args.auth}")

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

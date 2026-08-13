#!/usr/bin/env python3

import sys
import platform

# Ensure the script is run with a compatible Python version.
if sys.version_info < (3, 11):
    print("Error: Wormhole requires Python 3.11 or newer.", file=sys.stderr)
    sys.exit(1)

from .ad_blocker import update_database
from .auth_manager import add_user, modify_user, delete_user
from .context import RequestContext
from .logger import logger, setup_logger, format_log_message as flm
from .network_monitor import monitor_network_changes, is_ipv6_available
from .resolver import resolver
from .safeguards import load_ad_block_db, load_allowlist, load_blocklist
from .server import start_wormhole_server
from .version import VERSION
from argparse import ArgumentParser, Namespace
from pathlib import Path
from types import ModuleType
import asyncio
import signal


def select_event_loop():
    """Select the best available asyncio event loop implementation.

    Linux on x86_64/aarch64/riscv64 with CPython 3.13/3.14 prefers Talyn
    (https://github.com/cwt/talyn), which performs its own runtime safety
    checks; on any failure it falls back to uvloop.
    Windows uses Winloop (the Windows port of uvloop) without the extra guards.
    If no fast loop can be imported, returns None and the standard library
    asyncio loop is used instead.

    Only the module is imported here; the actual install() is deferred to main()
    so that importing this module does not install a global event loop policy.
    """
    if (
        sys.platform == "linux"
        and platform.machine() in ("x86_64", "aarch64", "riscv64")
        and sys.version_info[:2] in ((3, 13), (3, 14))
    ):
        try:
            import talyn

            return talyn
        except ImportError:
            pass
    try:
        if sys.platform == "win32":
            import winloop

            return winloop
        import uvloop

        return uvloop
    except ImportError:
        return None


fastloop = select_event_loop()


async def main_async(args: Namespace) -> None:
    """
    Asynchronously starts and runs the Wormhole server with the provided arguments.

    Args:
        args (Namespace): The parsed command-line arguments.

    Returns:
        None
    """
    # Use a loop instead of recursion to avoid stack overflow on repeated restarts
    while True:
        should_restart = await _run_server_once(args)
        if not should_restart:
            break


async def _run_server_once(args: Namespace) -> bool:
    """Run a single server instance (called in a loop for restarts).

    Returns:
        bool: True if the server should be restarted, False otherwise.
    """
    should_restart = False
    if fastloop:
        logger.info(
            flm(
                f"Using high-performance event loop: {fastloop.__name__}",
                ident={"id": "000000", "client": args.host},
                verbose=args.verbose,
            )
        )
    else:
        logger.info(
            flm(
                "Using standard asyncio event loop.",
                ident={"id": "000000", "client": args.host},
                verbose=args.verbose,
            )
        )

    # Initialize the resolver with the configured verbosity.
    resolver.initialize(verbose=args.verbose)

    if args.allowlist:
        # Create a context for the allowlist loading
        context = RequestContext(
            ident={"id": "000000", "client": args.host}, verbose=args.verbose
        )
        num_allowed = load_allowlist(
            args.allowlist,
            args.host,
            context,
        )
        if num_allowed > 0:
            logger.info(
                flm(
                    f"Loaded custom allowlist. Total allowlist size: {num_allowed} domains.",
                    context.ident,
                    context.verbose,
                )
            )

    if args.blocklist:
        # Create a context for the blocklist loading
        context = RequestContext(
            ident={"id": "000000", "client": args.host}, verbose=args.verbose
        )
        num_blocked = load_blocklist(
            args.blocklist,
            args.host,
            context,
        )
        if num_blocked > 0:
            logger.info(
                flm(
                    f"Loaded custom blocklist. Total blocklist size: {num_blocked} domains.",
                    context.ident,
                    context.verbose,
                )
            )

    if args.ad_block_db:
        # Create a context for the ad-block database loading
        context = RequestContext(
            ident={"id": "000000", "client": args.host}, verbose=args.verbose
        )
        num_blocked = await load_ad_block_db(
            args.ad_block_db,
            args.host,
            context,
        )
        if num_blocked > 0:
            logger.info(
                flm(
                    f"Ad-blocker enabled with {num_blocked} domains from database.",
                    context.ident,
                    context.verbose,
                )
            )

    # Import network monitoring utilities
    from .network_monitor import monitor_network_changes, is_ipv6_available

    # Set up shutdown and restart events
    shutdown_event = asyncio.Event()
    restart_event = asyncio.Event()

    def _shutdown_handler():
        """Handles shutdown signals to gracefully stop the server."""
        shutdown_event.set()

    def _restart_handler():
        """Handles restart signals to restart the server with updated network settings."""
        restart_event.set()

    # Set up signal handlers for graceful shutdown.
    loop = asyncio.get_running_loop()
    [
        loop.add_signal_handler(sig, _shutdown_handler)
        for sig in (signal.SIGINT, signal.SIGTERM)
    ]

    # Start the Wormhole server with the provided arguments.
    # Enable dual-stack if requested and IPv6 is available
    dual_stack = getattr(args, "auto_ipv6", False) and is_ipv6_available()

    server = await start_wormhole_server(
        args.host,
        args.port,
        args.auth,
        args.verbose,
        args.allow_private,
        dual_stack=dual_stack,
    )

    # Log the server startup completion, 000000 means internal server ID.
    logger.info(
        flm(
            "Server startup complete. Waiting for connections...",
            ident={"id": "000000", "client": args.host},
            verbose=args.verbose,
        )
    )

    # Start network monitoring if enabled
    network_monitor_task = None
    if getattr(args, "auto_ipv6", False):
        logger.info(
            flm(
                "Network monitoring enabled for IPv6 changes.",
                ident={"id": "000000", "client": args.host},
                verbose=args.verbose,
            )
        )
        network_monitor_task = asyncio.create_task(
            monitor_network_changes(verbose=args.verbose, host=args.host)
        )

        # Create a task to handle network change notifications
        async def handle_network_changes():
            try:
                await network_monitor_task
                # If network monitor completes, it means IPv6 became available
                _restart_handler()
            except Exception as e:
                logger.error(
                    flm(
                        f"Network monitoring error: {e}",
                        ident={"id": "000000", "client": args.host},
                        verbose=args.verbose,
                    )
                )

        asyncio.create_task(handle_network_changes())

    # Main event loop - wait for shutdown, restart, or network change signals
    try:
        # Create tasks from the coroutines
        shutdown_task = asyncio.create_task(shutdown_event.wait())
        pending_tasks = [shutdown_task]

        if getattr(args, "auto_ipv6", False):
            restart_task = asyncio.create_task(restart_event.wait())
            pending_tasks.append(restart_task)

        done, pending = await asyncio.wait(
            pending_tasks, return_when=asyncio.FIRST_COMPLETED
        )

        # Cancel any remaining tasks
        for task in pending:
            task.cancel()

        # Check which event completed
        if restart_event.is_set():
            logger.info(
                flm(
                    "Restart signal received, closing server for restart...",
                    ident={"id": "000000", "client": args.host},
                    verbose=args.verbose,
                )
            )
        elif shutdown_event.is_set():
            logger.info(
                flm(
                    f"Shutdown signal received, closing server...",
                    ident={"id": "000000", "client": args.host},
                    verbose=args.verbose,
                )
            )

    finally:
        # Gracefully shut down the server.
        server.close()
        await server.wait_closed()
        logger.info(
            flm(
                f"Server has been shut down gracefully.",
                ident={"id": "000000", "client": args.host},
                verbose=args.verbose,
            )
        )

        # Restart if needed (but not in test environments)
        if restart_event.is_set() and not getattr(args, "_test_mode", False):
            logger.info(
                flm(
                    "Restarting server...",
                    ident={"id": "000000", "client": args.host},
                    verbose=args.verbose,
                )
            )
            # Reset events for restart
            shutdown_event.clear()
            restart_event.clear()
            should_restart = True
    return should_restart


def main() -> int:
    """
    Parses command-line arguments and starts the event loop.

    This function handles the main execution flow of the Wormhole proxy server.
    It parses command-line arguments, sets up logging, and initializes the server.
    If the server is not in update mode, it runs the main server loop asynchronously.
    If in update mode, it updates the ad-block database and exits.

    Returns:
        int: The exit code of the script.
    """
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
        "--auto-ipv6",
        action="store_true",
        help="Automatically detect IPv6 availability and restart server when IPv6 becomes available",
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
    ad_block_group.add_argument(
        "--blocklist",
        default=None,
        help="Path to a file of domains to block (inverted allowlist).",
    )
    args = parser.parse_args()

    # --- Utility Command Handling ---
    # These commands run synchronously and exit.
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

    if args.auth_add:
        return add_user(args.auth_add[0], args.auth_add[1])
    if args.auth_mod:
        return modify_user(args.auth_mod[0], args.auth_mod[1])
    if args.auth_del:
        return delete_user(args.auth_del[0], args.auth_del[1])

    # --- Server and DB Update Handling ---
    # Determine if we are running the full async server or a utility.
    is_server_mode = not args.update_ad_block_db

    # Run a coroutine on the selected fast event loop, falling back to the
    # standard library asyncio loop when the optimized loop cannot actually run
    # (e.g. Talyn raises while creating its loop in this environment).
    def _run_async(coro_factory) -> None:
        started = False

        async def wrap_coro():
            nonlocal started
            started = True
            return await coro_factory()

        try:
            if fastloop is not None:
                if hasattr(fastloop, "run"):
                    fastloop.run(wrap_coro())
                    return
                fastloop.install()
            asyncio.run(wrap_coro())
        except Exception:
            if fastloop is not None and not started:
                # Optimized loop failed at runtime setup; retry on plain asyncio.
                logger.warning(
                    "Optimized event loop %s unavailable; using standard asyncio.",
                    fastloop.__name__,
                )
                asyncio.set_event_loop_policy(None)
                asyncio.run(coro_factory())
            else:
                raise

    # Setup logging. Disable async features for synchronous utility commands.
    setup_logger(
        args.syslog_host,
        args.syslog_port,
        args.verbose,
        async_mode=is_server_mode,
    )

    if args.update_ad_block_db:
        # For this standalone utility, configure a simple logger to show progress.
        logger.info(f"Updating ad-block database at: {args.update_ad_block_db}")

        def run_update():
            return update_database(
                args.update_ad_block_db, args.allowlist, args.blocklist
            )

        try:
            _run_async(run_update)
        except Exception as e:
            logger.error(f"\nAn error occurred during update: {e}")
            return 1
        return 0

    # --- Main Server Execution ---
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535.")

    if args.auth and not Path(args.auth).is_file():
        parser.error(f"Authentication file not found: {args.auth}")

    def run_main():
        return main_async(args)

    try:
        _run_async(run_main)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
    except Exception as e:
        # Catch-all for critical startup errors, like binding failure.
        print(f"A critical error occurred: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

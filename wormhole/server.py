from .authentication import get_ident, verify_credentials
from .handler import process_http_request, process_https_tunnel, parse_request
from .logger import logger, format_log_message as flm
from time import time
import asyncio
import functools
import socket
import sys

# --- Constants ---
MAX_RETRY: int = 3
MAX_TASKS: int = 1024  # Default value, will be overridden below if possible.
# Determine the maximum number of concurrent tasks based on the OS limit for open files.
# We use 90% of the limit to leave a buffer for other system operations.
try:
    if sys.platform == "win32":
        import win32file  # noqa

        MAX_TASKS = int(0.9 * win32file._getmaxstdio())
    else:
        import resource

        MAX_TASKS = int(0.9 * resource.getrlimit(resource.RLIMIT_NOFILE)[0])
except (ImportError, ValueError):
    pass  # If we can't determine the limit, fall back to the default value.
CURRENT_TASKS = 0

# --- Main Connection Handler ---


async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    auth_file_path: str | None,
    verbose: int = 0,
    allow_private: bool = False,
) -> None:
    """
    Manages a single client connection from start to finish.
    """
    global CURRENT_TASKS
    ident = get_ident(client_reader, client_writer)
    start_time = time()

    CURRENT_TASKS += 1
    if verbose > 0:
        logger.debug(
            flm(f"{CURRENT_TASKS}/{MAX_TASKS} Tasks active", ident, verbose)
        )
    else:
        logger.debug(flm("Connection started.", ident, verbose))

    try:
        # Parse the initial request from the client.
        request_line, headers, payload = await parse_request(
            client_reader, ident, verbose
        )
        # If parse_request fails, it returns (None, None, None). We check all three
        # to explicitly narrow the types for mypy, which can't infer that if one
        # is None, they all are.
        if not request_line or headers is None or payload is None:
            logger.debug(
                flm("Empty request, closing connection.", ident, verbose)
            )
            return

        # Split the request line into its components.
        try:
            method, uri, version = request_line.split(" ", 2)
        except ValueError:
            logger.debug(
                flm(
                    f"Malformed request line '{request_line}', closing.",
                    ident,
                    verbose,
                )
            )
            return

        # --- Authentication Check ---
        if auth_file_path:
            # Pass method for Digest authentication calculation
            user_ident = await verify_credentials(
                client_reader,
                client_writer,
                method,
                headers,
                auth_file_path,
            )
            if user_ident is None:
                logger.info(
                    flm(
                        f"{method} 407 {uri} (Authentication Failed)",
                        ident,
                        verbose,
                    )
                )
                return
            ident = user_ident  # Update ident with authenticated user info.
        # --- Request Dispatching ---
        if method.upper() == "CONNECT":
            await process_https_tunnel(
                client_reader,
                client_writer,
                method,
                uri,
                ident,
                allow_private,
                max_attempts=MAX_RETRY,
                verbose=verbose,
            )
        else:
            # The check above ensures `headers` is `list[str]` and `payload` is `bytes`.
            await process_http_request(
                client_writer,
                method,
                uri,
                version,
                headers,
                payload,
                ident,
                allow_private,
                max_attempts=MAX_RETRY,
                verbose=verbose,
            )

    except Exception as e:
        logger.error(
            flm(f"Unhandled error in connection handler: {e}", ident, verbose),
            exc_info=True,
        )
    finally:
        CURRENT_TASKS -= 1
        if not client_writer.is_closing():
            client_writer.close()
            await client_writer.wait_closed()
        duration = time() - start_time
        logger.debug(
            flm(f"Connection closed ({duration:.5f} seconds).", ident, verbose)
        )


async def start_wormhole_server(
    host: str,
    port: int,
    auth_file_path: str | None,
    verbose: int = 0,
    allow_private: bool = False,
) -> asyncio.Server:
    """
    Initializes and starts the main proxy server.
    """
    # Use functools.partial to pass the auth_file_path and verbose flag to the connection handler.
    connection_handler = functools.partial(
        handle_connection,
        auth_file_path=auth_file_path,
        verbose=verbose,
        allow_private=allow_private,
    )

    try:
        # Determine address family for IPv4/IPv6.
        family = socket.AF_INET6 if ":" in host else socket.AF_INET

        server = await asyncio.start_server(
            connection_handler, host, port, family=family, limit=MAX_TASKS
        )

        # Log the addresses the server is listening on.
        for s in server.sockets:
            addr = s.getsockname()
            logger.info(
                flm(
                    f"Wormhole proxy bound and listening at {addr[0]}:{addr[1]}",
                    ident={"id": "000000", "client": host},
                    verbose=verbose,
                )
            )

        return server

    except OSError as e:
        logger.critical(
            flm(
                f"Failed to bind server at {host}:{port}: {e}",
                ident={"id": "000000", "client": host},
                verbose=verbose,
            )
        )
        raise

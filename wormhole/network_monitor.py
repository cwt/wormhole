"""Network monitoring utilities for detecting IPv6 availability."""

import asyncio
import socket
from .logger import logger, format_log_message as flm


def is_ipv6_available() -> bool:
    """
    Check if IPv6 is available on the system.

    Returns:
        bool: True if IPv6 is available, False otherwise.
    """
    try:
        # Try to create an IPv6 socket
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            # Try to connect to a well-known IPv6 address
            sock.bind(("::1", 0))
        return True
    except (socket.error, OSError):
        return False


def has_ipv6_connectivity() -> bool:
    """
    Check if there's actual IPv6 connectivity by attempting to connect
    to a known IPv6 address.

    Returns:
        bool: True if IPv6 connectivity is available, False otherwise.
    """
    try:
        # Try to connect to Google's IPv6 DNS server
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)  # 3 second timeout
            sock.connect(("2001:4860:4860::8888", 53))
        return True
    except (socket.error, OSError):
        return False


async def monitor_network_changes(
    check_interval: int = 60, verbose: int = 0, host: str = "0.0.0.0"
) -> bool:
    """
    Monitor network changes and detect when IPv6 becomes available.

    Args:
        check_interval (int): How often to check for network changes (in seconds)
        verbose (int): Verbosity level for logging
        host (str): Host address being monitored

    Returns:
        bool: True when IPv6 becomes available, False on error or interruption
    """
    ident = {"id": "network_monitor", "client": host}

    # Initial state
    ipv6_available = is_ipv6_available()
    ipv6_connectivity = has_ipv6_connectivity() if ipv6_available else False

    logger.info(
        flm(
            f"Network monitoring started. IPv6 available: {ipv6_available}, "
            f"IPv6 connectivity: {ipv6_connectivity}",
            ident,
            verbose,
        )
    )

    while True:
        try:
            await asyncio.sleep(check_interval)

            # Check current state
            current_ipv6_available = is_ipv6_available()
            current_ipv6_connectivity = (
                has_ipv6_connectivity() if current_ipv6_available else False
            )

            # Check if IPv6 just became available BEFORE updating state
            # If IPv6 just became available, notify
            if current_ipv6_available and not ipv6_available:
                logger.info(
                    flm(
                        "IPv6 support detected. Server restart recommended for dual-stack support.",
                        ident,
                        verbose,
                    )
                )
                return True

            # Log changes and update state
            if current_ipv6_available != ipv6_available:
                logger.info(
                    flm(
                        f"IPv6 availability changed: {ipv6_available} -> {current_ipv6_available}",
                        ident,
                        verbose,
                    )
                )
                ipv6_available = current_ipv6_available

            if current_ipv6_connectivity != ipv6_connectivity:
                logger.info(
                    flm(
                        f"IPv6 connectivity changed: {ipv6_connectivity} -> {current_ipv6_connectivity}",
                        ident,
                        verbose,
                    )
                )
                ipv6_connectivity = current_ipv6_connectivity

        except asyncio.CancelledError:
            logger.info(
                flm(
                    "Network monitoring cancelled.",
                    ident,
                    verbose,
                )
            )
            break
        except Exception as e:
            logger.error(
                flm(
                    f"Error in network monitoring: {e}",
                    ident,
                    verbose,
                )
            )

    return False

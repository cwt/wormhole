from loguru import logger
import logging.handlers
import os
import sys

# In loguru, the logger is imported and ready to be configured.
# We just need to ensure other modules import this configured instance.


def setup_logger(
    syslog_host: str | None = None, syslog_port: int = 514, verbose: int = 0
) -> None:
    """
    Configures the global loguru logger instance. This should only be called once.
    """
    # Remove the default handler to have full control over sinks.
    logger.remove()

    # Set logging level based on verbosity.
    if verbose >= 2:
        level = "DEBUG"
    elif verbose >= 1:
        level = "DEBUG"
    else:
        level = "INFO"

    # --- Console Sink ---
    # Loguru automatically adds contextual data. The format is simpler.
    console_format = (
        "<green>{time:MMM D HH:mm:ss}</green> "
        "<cyan>{name}</cyan>[<cyan>{process}</cyan>]: "
        "<level>{message}</level>"
    )
    logger.add(sys.stderr, level=level, format=console_format)

    # --- Syslog Sink ---
    if syslog_host and syslog_host != "DISABLED":
        # Create a standard library syslog handler instance.
        # Loguru can sink to handler objects directly.
        if syslog_host.startswith("/") and os.path.exists(syslog_host):
            handler = logging.handlers.SysLogHandler(address=syslog_host)
            syslog_format = "{time:MMM D HH:mm:ss} {name}[{process}]: {message}"
        else:
            handler = logging.handlers.SysLogHandler(
                address=(syslog_host, syslog_port)
            )
            # For network syslog, the hostname is typically added by the syslog server,
            # but we can include it if needed.
            syslog_format = "{time:MMM D HH:mm:ss} {extra[hostname]} {name}[{process}]: {message}"
            # Add hostname to all log records.
            logger.configure(extra={"hostname": os.uname().nodename})

        logger.add(handler, level="INFO", format=syslog_format)

    # Suppress overly verbose asyncio logger messages unless in high verbosity.
    logging.getLogger("asyncio").setLevel(
        logging.DEBUG if verbose >= 2 else logging.CRITICAL
    )

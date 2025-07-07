import logging  # noqa
import logging.handlers
import os
import socket

# --- Context Filter for Syslog ---


class ContextFilter(logging.Filter):
    """Injects the hostname into log records for syslog formatting."""

    hostname: str = socket.gethostname()

    def filter(self, record: logging.LogRecord) -> bool:
        record.hostname = self.hostname
        return True


# --- Module-level Logger (The Singleton) ---

# In Python, modules are singletons. We create the logger instance here once.
# It will be configured by `setup_logger` and then imported by other modules.
logger = logging.getLogger("wormhole")


# --- Configuration Function ---


def setup_logger(
    syslog_host: str | None = None, syslog_port: int = 514, verbose: int = 0
) -> None:
    """
    Configures the global logger instance. This should only be called once.
    """
    # Prevent re-configuration if handlers are already present.
    if logger.handlers:
        return

    # Set logging level based on verbosity.
    logger.setLevel(logging.INFO)
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)

    if verbose >= 1:
        logger.setLevel(logging.DEBUG)
    if verbose >= 2:
        logging.getLogger("asyncio").setLevel(logging.DEBUG)

    # --- Console Handler ---
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(name)s[%(process)d]: %(message)s",
            datefmt="%b %d %H:%M:%S",
        )
    )
    logger.addHandler(console_handler)

    # --- Syslog Handler ---
    if syslog_host and syslog_host != "DISABLED":
        # Handle local syslog socket vs. network host.
        if syslog_host.startswith("/") and os.path.exists(syslog_host):
            syslog_handler = logging.handlers.SysLogHandler(address=syslog_host)
            formatter = logging.Formatter(
                "%(asctime)s %(name)s[%(process)d]: %(message)s",
                datefmt="%b %d %H:%M:%S",
            )
        else:
            logger.addFilter(ContextFilter())
            syslog_handler = logging.handlers.SysLogHandler(
                address=(syslog_host, syslog_port)
            )
            formatter = logging.Formatter(
                "%(asctime)s %(hostname)s %(name)s[%(process)d]: %(message)s",
                datefmt="%b %d %H:%M:%S",
            )

        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)

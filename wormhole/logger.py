from loguru import logger
import asyncio
import logging.handlers
import os
import sys


class LogThrottler:
    """A class to throttle and summarize repeated log messages."""

    def __init__(self, logger, level: str, delay: float = 5.0):
        """
        Initializes the log throttler with a logger instance, log level, and delay.

        Args:
            logger (logger): The logger instance to use.
            level (str): The log level name (e.g., 'error').
            delay (float): The delay time in seconds before logging a repeated message summary.
        """
        self.logger = logger
        self.level = level.upper()  # Store the level name, e.g., "ERROR"
        self.delay = delay
        self.last_message: str | None = None
        self.repeat_count: int = 0
        self.timer: asyncio.TimerHandle | None = None

    def _flush_summary(self, **kwargs):
        """
        Prints the summary of how many times the last message was repeated.

        This method is responsible for logging the summary of repeated messages to the
        logger. It checks the repeat count and logs the appropriate message format.

        Args:
            **kwargs: Additional keyword arguments to be passed to the logger.
        """
        if self.repeat_count > 2:
            self.logger.opt(depth=2).log(
                self.level,
                f"{self.last_message} "
                f"(and {self.repeat_count -1} more in the last {self.delay} seconds.)",
                **kwargs,
            )
        elif self.repeat_count == 2:
            # If the message was repeated only once, we log it directly.
            self.logger.opt(depth=2).log(
                self.level, self.last_message, **kwargs
            )

        # Reset the state
        self.timer = None
        self.last_message = None
        self.repeat_count = 0

    def process(self, message: str, **kwargs):
        """
        Processes a log message, either logging it or incrementing a repeat counter.

        This method checks if the current message is the same as the last one. If it is,
        it increments the repeat counter. If it's a new message, it logs the message
        immediately and resets the repeat counter. If the message has been repeated multiple
        times, it schedules a delayed summary log message.

        Args:
            message (str): The log message to process.
            **kwargs: Additional keyword arguments to be passed to the logger.
        """
        if self.last_message and message != self.last_message:
            if self.timer:
                self.timer.cancel()
            self._flush_summary()

        if message == self.last_message:
            self.repeat_count += 1
        else:
            # It's a new message. Log it immediately, but look 1 frame up the stack.
            # This ensures the log record shows the original caller (e.g., wormhole.handler).
            self.logger.opt(depth=1).log(self.level, message, **kwargs)
            self.last_message = message
            self.repeat_count = 1

        if self.timer:
            self.timer.cancel()

        loop = asyncio.get_running_loop()
        self.timer = loop.call_later(self.delay, self._flush_summary)


# In loguru, the logger is imported and ready to be configured.
# We just need to ensure other modules import this configured instance.
def setup_logger(
    syslog_host: str | None = None,
    syslog_port: int = 514,
    verbose: int = 0,
    async_mode: bool = True,
) -> None:
    """
    Sets up the global loguru logger instance, configuring sinks based on the provided parameters.

    Args:
        syslog_host (str | None, optional): The host for the syslog server. Defaults to None.
        syslog_port (int, optional): The port for the syslog server. Defaults to 514.
        verbose (int, optional): The verbosity level. Defaults to 0.
        async_mode (bool, optional): Whether to use async mode. Defaults to True.
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

    # Only enable the async LogThrottler if we are in async mode.
    if async_mode and verbose < 2:
        logger.info = LogThrottler(logger, "info").process  # type: ignore
        logger.warning = LogThrottler(logger, "warning").process  # type: ignore
        logger.error = LogThrottler(logger, "error").process  # type: ignore


def format_log_message(
    message: str, ident: dict[str, str], verbose: int
) -> str:
    """
    Formats a log message with the given identifier.

    Args:
        message (str): The log message to format.
        ident (dict[str, str]): A dictionary containing the unique identifier and client details.
        verbose (int): The verbosity level of the logger.

    Returns:
        str: A formatted log message string.
    """
    if verbose > 1:
        return f"[{ident['id']}][{ident['client']}]: {message}"
    else:
        return f"[{ident['client']}]: {message}"

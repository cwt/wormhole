import logging
import logging.handlers
import os

import socket

from datetime import datetime


class ContextFilter(logging.Filter):

    hostname: str = socket.gethostname()

    def filter(self, record: logging.LogRecord) -> bool:
        record.hostname = self.hostname
        return True


class Singleton(type):
    _instances: dict[type, object] = {}

    def __call__(cls, *args: tuple, **kwargs: dict) -> object:
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class Logger(metaclass=Singleton):
    def __init__(
        self, syslog_host: str | None = None, syslog_port: int = 514, verbose: int = 0
    ) -> None:
        self.logger = logging.getLogger("wormhole")
        self.logger.setLevel(logging.INFO)
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)

        if verbose >= 1:
            self.logger.setLevel(logging.DEBUG)
        if verbose >= 2:
            logging.getLogger("asyncio").setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(name)s[%(process)d]: %(message)s",
                datefmt="%b %d %H:%M:%S",
            )
        )
        self.logger.addHandler(console_handler)

        # Syslog handler
        if syslog_host and syslog_host != "DISABLED":
            if syslog_host.startswith("/") and os.path.exists(syslog_host):
                syslog = logging.handlers.SysLogHandler(address=syslog_host)
                syslog.setFormatter(
                    logging.Formatter(
                        "%(asctime)s %(name)s[%(process)d]: %(message)s",
                        datefmt="%b %d %H:%M:%S",
                    )
                )
            else:
                self.logger.addFilter(ContextFilter())
                syslog = logging.handlers.SysLogHandler(
                    address=(syslog_host, syslog_port)
                )

                syslog.setFormatter(
                    logging.Formatter(
                        "%(asctime)s %(hostname)s %(name)s[%(process)d]: %(message)s",
                        datefmt="%b %d %H:%M:%S",
                    )
                )
            self.logger.addHandler(syslog)

    def get_logger(self) -> logging.Logger:
        return self.logger

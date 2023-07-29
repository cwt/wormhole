import logging
import logging.handlers
import os
import socket


class ContextFilter(logging.Filter):
    hostname = socket.gethostname()

    def filter(self, record):
        record.hostname = self.hostname
        return True


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(
                *args, **kwargs
            )
        return cls._instances[cls]


class Logger(metaclass=Singleton):
    def __init__(self, syslog_host=None, syslog_port=514, verbose=0):
        unix_format = "%(asctime)s %(name)s[%(process)d]: %(message)s"
        net_format = (
            "%(asctime)s %(hostname)s %(name)s[%(process)d]: %(message)s"
        )
        date_format = "%b %d %H:%M:%S"

        self.logger = logging.getLogger("wormhole")
        self.logger.setLevel(logging.INFO)
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
        if verbose >= 1:
            self.logger.setLevel(logging.DEBUG)
        if verbose >= 2:
            logging.getLogger("asyncio").setLevel(logging.DEBUG)

        # Add console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(unix_format, datefmt=date_format)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        if syslog_host and syslog_host != "DISABLED":
            if syslog_host.startswith("/") and os.path.exists(syslog_host):
                syslog = logging.handlers.SysLogHandler(
                    address=syslog_host,
                )
                formatter = logging.Formatter(unix_format, datefmt=date_format)
            else:
                self.logger.addFilter(ContextFilter())
                syslog = logging.handlers.SysLogHandler(
                    address=(syslog_host, syslog_port),
                )
                formatter = logging.Formatter(net_format, datefmt=date_format)
            syslog.setFormatter(formatter)
            self.logger.addHandler(syslog)

    def get_logger(self):
        return self.logger

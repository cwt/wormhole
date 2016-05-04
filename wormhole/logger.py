import logging
import logging.handlers
import os
import socket


class ContextFilter(logging.Filter):
    hostname = socket.gethostname()

    def filter(self, record):
        record.hostname = self.hostname
        return True


logger = None
def get_logger(syslog_host=None, syslog_port=514):
    global logger
    if logger is None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(name)s[%(process)d]: %(message)s'
        )
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)
        logger = logging.getLogger('wormhole')
        if syslog_host and syslog_host != 'DISABLED':
            if syslog_host.startswith('/') and os.path.exists(syslog_host):
                syslog = logging.handlers.SysLogHandler(
                    address=syslog_host,
                )
                formatter = logging.Formatter(
                '%(asctime)s %(name)s[%(process)d]: %(message)s',
                datefmt='%b %d %H:%M:%S')
            else:
                logger.addFilter(ContextFilter())
                syslog = logging.handlers.SysLogHandler(
                    address=(syslog_host, syslog_port),
                )
                formatter = logging.Formatter(
                '%(asctime)s %(hostname)s %(name)s[%(process)d]: %(message)s',
                datefmt='%b %d %H:%M:%S')
            syslog.setFormatter(formatter)
            logger.addHandler(syslog)
    return logger

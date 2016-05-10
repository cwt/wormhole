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
def get_logger(syslog_host=None, syslog_port=514, verbose=0):
    unix_format = '%(asctime)s %(name)s[%(process)d]: %(message)s'
    net_format = '%(asctime)s %(hostname)s %(name)s[%(process)d]: %(message)s'
    date_format = '%b %d %H:%M:%S'

    global logger
    if logger is None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(name)s[%(process)d]: %(message)s'
        )
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)
        logger = logging.getLogger('wormhole')
        if verbose >= 1:
            logger.setLevel(logging.DEBUG)
        if verbose >= 2:
            logging.getLogger('asyncio').setLevel(logging.DEBUG)
        if syslog_host and syslog_host != 'DISABLED':
            if syslog_host.startswith('/') and os.path.exists(syslog_host):
                syslog = logging.handlers.SysLogHandler(
                    address=syslog_host,
                )
                formatter = logging.Formatter(unix_format, datefmt=date_format)
            else:
                logger.addFilter(ContextFilter())
                syslog = logging.handlers.SysLogHandler(
                    address=(syslog_host, syslog_port),
                )
                formatter = logging.Formatter(net_format, datefmt=date_format)
            syslog.setFormatter(formatter)
            logger.addHandler(syslog)
    return logger

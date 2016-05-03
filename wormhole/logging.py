import logging

logger = None


def get_logger():
    global logger
    if logger is None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(name)s[%(process)d]: %(message)s'
        )
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)
        logger = logging.getLogger('wormhole')
    return logger

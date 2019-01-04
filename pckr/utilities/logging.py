import logging
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')


def setup_logger(name, log_file, level=logging.INFO):
    """
    Function setup as many loggers as you want
    """

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


assert_logger = setup_logger('assert_logger', 'logs/assert.log')
surface_logger = setup_logger('surface', 'logs/surface.log')
debug_logger = setup_logger('debug', 'logs/debug.log', level=logging.DEBUG)
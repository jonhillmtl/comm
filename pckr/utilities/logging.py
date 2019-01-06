"""
this file contains functions to set up loggers as well as predefined loggers.

you could for instance:

from ..utilities.logging import assert_logger, debug_logger
assert_logger.error("error message")

"""

import logging
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')


def setup_logger(
    name: str,
    log_file: str,
    level: int = logging.INFO
) -> logging.Logger:
    """
    Function setup as many loggers as you want.

    Parameters
    ----------
    name: str
    log_file: str
    level: int

    Returns
    -------
    logging.Logger
        the logger that was created
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

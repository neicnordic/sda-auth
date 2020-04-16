import logging
from sys import stdout


EGA_FORMAT = '[%(asctime)s] - EGA -  %(message)s'
ELIXIR_FORMAT = '[%(asctime)s] - ELIXIR -  %(message)s'
DEFAULT_FORMAT = '[%(asctime)s] - %(module)s - %(message)s'


def setup_custom_loggers(loglevel):
    """Set up custom loggers for different modules."""
    ega_handler = logging.StreamHandler(stdout)
    ega_logger = logging.getLogger('ega')
    formatter = logging.Formatter(EGA_FORMAT)
    ega_handler.setFormatter(formatter)
    ega_logger.setLevel(loglevel)
    ega_logger.addHandler(ega_handler)

    elixir_handler = logging.StreamHandler(stdout)
    elixir_logger = logging.getLogger('elixir')
    formatter = logging.Formatter(ELIXIR_FORMAT)
    elixir_handler.setFormatter(formatter)
    elixir_logger.setLevel(loglevel)
    elixir_logger.addHandler(elixir_handler)

    default_handler = logging.StreamHandler(stdout)
    default_logger = logging.getLogger('default')
    formatter = logging.Formatter(DEFAULT_FORMAT)
    default_handler.setFormatter(formatter)
    default_logger.setLevel(loglevel)
    default_logger.addHandler(default_handler)

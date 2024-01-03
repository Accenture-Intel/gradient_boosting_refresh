import sys, logging
from .utils import DEBUG_MODE
logger_set = False

def set_logger(log_filename, logger_name=None):
    log_formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s') 
    log_formatter.default_msec_format = '%s.%03d'
    log = logging.getLogger(logger_name)
    if DEBUG_MODE:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(log_formatter)
    log.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    log.addHandler(console_handler)
    return log

def get_logger(logger_name=None):
    return logging.getLogger(logger_name)

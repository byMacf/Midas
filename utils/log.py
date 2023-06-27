import logging
import sys
import os
import inspect

from datetime import datetime

def get_loggers():
    '''
	Summary:
	Creates 3 loggers with the same datetime; midasd-logger (DHCP), midast-logger (Topology), midasp-logger (Provisioning).
    Each logger has a different emoji to make log sources easily identifiable.
	'''
    now = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    for logger_name in ['midasd-logger', 'midast-logger', 'midasp-logger']:
        logger = logging.getLogger(logger_name)

        logger.setLevel(logging.DEBUG)
        if logger_name == 'midasd-logger':
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] \U0001F916 | %(message)s')
        elif logger_name == 'midast-logger':
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] \U0001F47E | %(message)s')
        elif logger_name == 'midasp-logger':
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] \U0001F47D | %(message)s')

        file_handler = logging.FileHandler(os.getcwd() + '/logs/midas_' + now + '.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

def log(log_message, level):
    '''
	Summary:
	Logs information to logfile at the specified level.

    Takes:
    log_message: Information to log
    level: Level of which to log the information at
	'''
    caller_filename = inspect.stack()[1].filename 

    if 'midasd' in caller_filename:
        logger = logging.getLogger('midasd-logger')
    elif 'midast' in caller_filename:
        logger = logging.getLogger('midast-logger')
    elif 'midasp' in caller_filename:
        logger = logging.getLogger('midasp-logger')

    log_message_types = {
        'debug': logger.debug,
        'info': logger.info,
        'warning': logger.warning,
        'error': logger.error,
        'critical': logger.critical
    }

    log_message_types[level](log_message)

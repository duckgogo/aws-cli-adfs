import logging

from .constants import AWS_ADFS_LOG_FILE


log_handler = logging.FileHandler(AWS_ADFS_LOG_FILE)
logger = logging.getLogger('aws-adfs')
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)

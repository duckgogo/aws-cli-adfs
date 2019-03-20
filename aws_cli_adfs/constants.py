import os


# config file path
DOT_AWS = os.path.expanduser('~/.aws/')
AWS_CREDENTIALS_FILE = os.path.join(DOT_AWS, 'credentials')
AWS_CONFIG_FILE = os.path.join(DOT_AWS, 'config')
AWS_ADFS_CONFIG_FILE = os.path.join(DOT_AWS, 'aws-adfs.toml')
AWS_ADFS_LOG_FILE = os.path.join(DOT_AWS, 'aws-adfs.log')

# profile defaults
DEFAULT_IDP_SESSION_DURATION = 43200
DEFAULT_OUTPUT_FORMAT = 'json'

from datetime import datetime
from getpass import getuser

import click

from .constants import *
from .utils import *


def init():

    # create ~/.aws directory if not exists
    if not os.path.exists(DOT_AWS):
        os.mkdir(DOT_AWS)

    # create aws credentials file if not exists
    aws_credentials = read_aws_credentials(AWS_CREDENTIALS_FILE)
    default_profile = aws_credentials['default']
    if 'aws_access_key_id' not in default_profile:
        aws_credentials.set(
            'default',
            'aws_access_key_id',
            ''
        )
    if 'aws_secret_access_key' not in default_profile:
        aws_credentials.set(
            'default',
            'aws_secret_access_key',
            ''
        )
    save_aws_credentials(AWS_CREDENTIALS_FILE, aws_credentials)

    # create aws config file if not exists
    aws_config = read_aws_config(AWS_CONFIG_FILE)
    if 'region' not in aws_config['default']:
        aws_config.set('default', 'region', '')
    save_aws_config(AWS_CONFIG_FILE, aws_config)

    # create aws-adfs config file if not exists
    if not os.path.exists(AWS_ADFS_CONFIG_FILE):
        save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, dict())


def welcome():

    aws_adfs_config = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    last_execution_time = datetime.strptime(
        aws_adfs_config['execution_time'],
        '%Y-%m-%d %H:%M:%S'
    )
    now = datetime.now()
    aws_adfs_config['execution_time'] = now.strftime('%Y-%m-%d %H:%M:%S')
    save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_config)
    if last_execution_time.date() < now.date():
        user = getuser()
        if 6 <= now.hour <= 9:
            click.secho(
                'Good morning, {}!'.format(user),
                fg='green'
            )
        elif 14 <= now.hour < 18:
            click.secho(
                'Good afternoon, {}!'.format(user),
                fg='green'
            )
        elif 18 <= now.hour < 24:
            click.secho(
                'Good evening, {}!'.format(user),
                fg='green'
            )
        elif 0 <= now.hour < 6:
            click.secho(
                'Hi {}, it\'s very late now,'
                ' please take good care of yourself!'.format(
                    user
                ),
                fg='red'
            )
        else:
            click.secho(
                'Hello, {}!'.format(user),
                fg='green'
            )


init()
welcome()

__version__ = '0.1.3'

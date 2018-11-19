import configparser
import toml


def read_aws_adfs_config(filename):

    with open(filename, 'r') as f:
        aws_adfs_conf = toml.load(f)
    if not aws_adfs_conf.get('profiles'):
        aws_adfs_conf['profiles'] = dict()
    if not aws_adfs_conf.get('default-profile'):
        aws_adfs_conf['default-profile'] = ''
    if not aws_adfs_conf.get('execution_time'):
        aws_adfs_conf['execution_time'] = \
            '2018-11-18 22:28:07'
    return aws_adfs_conf


def save_aws_adfs_config(filename, conf):

    with open(filename, 'w+') as f:
        toml.dump(conf, f)


def read_aws_credentials(filename):

    aws_credentials = configparser.RawConfigParser()
    aws_credentials.read(filename)
    if not aws_credentials.has_section('default'):
        aws_credentials.add_section('default')
    return aws_credentials


def save_aws_credentials(filename, aws_credentials):

    with open(filename, 'w+') as f:
        aws_credentials.write(f)


def read_aws_config(filename):

    aws_config = configparser.RawConfigParser()
    aws_config.read(filename)
    if not aws_config.has_section('default'):
        aws_config.add_section('default')
    return aws_config


def save_aws_config(filename, aws_config):

    with open(filename, 'w+') as f:
        aws_config.write(f)

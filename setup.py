from setuptools import setup

from aws_cli_adfs import __version__

setup(
    name='awscli-adfs',
    version=__version__,
    author='duckgogo',
    author_email='zeng.jianxin@foxmail.com',
    url='https://github.com/duckgogo/aws-cli-adfs',
    description='Login to AWS CLI using Active Directory Federation Services.',
    py_modules=['aws_cli_adfs'],
    packages=['aws_cli_adfs'],
    include_package_data=True,
    python_requires='>=3.5',
    install_requires=[
        'awscli',
        'beautifulsoup4',
        'boto',
        'Click',
        'configparser',
        'requests',
        'toml'
    ],
    entry_points='''
        [console_scripts]
        aws-adfs = aws_cli_adfs.cli:cli
    ''',
)

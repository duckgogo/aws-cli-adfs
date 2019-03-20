import click
import re
import sys
from urllib import parse
from urllib.error import URLError

from .__init__ import __version__
from .constants import *
from .login import adfs_login
from .utils import *

from .constants import DEFAULT_IDP_SESSION_DURATION, DEFAULT_OUTPUT_FORMAT


# the cli is consist of three groups:
# profile management part, login part and version part


# profile management part

@click.group()
def profile_cli():

    pass


@profile_cli.group('profile', chain=True)
def profile():
    """Manage User Profiles"""

    pass


def exit_if_no_profile(aws_adfs_config):

    aws_adfs_profiles = aws_adfs_config['profiles']
    if not aws_adfs_profiles:
        ls_profiles()
        sys.exit(-1)


def exit_if_no_profile_is_provided(profile_names, default_profile):

    if not (profile_names or default_profile):
        click.echo('Default profile is not set.')
        click.echo('Run the following command to set it.')
        click.secho(
            '\taws-adfs profile default PROFILE-NAME',
            fg='blue'
        )
        sys.exit(-1)


def ls_profiles():
    """list all profiles"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    aws_adfs_profiles = aws_adfs_conf['profiles']
    if aws_adfs_profiles.keys():
        click.echo(
            'All your profile(s):  "{}"'.format(
                '", "'.join(aws_adfs_profiles.keys())
            )
        )
    else:
        click.secho(
            'You don\'t have any profiles.',
            fg='red'
        )
        click.echo('Run the following command to create one:')
        click.secho(
            '\taws-adfs profile create',
            fg='blue'
        )


def ls_profiles_if_profile_names_are_wrong(wrong_profile_names):

    if wrong_profile_names:
        click.secho(
            'Wrong profile names: "{}"'.format(
                '", "'.join(wrong_profile_names)
            ),
            fg='red'
        )
        ls_profiles()


def is_valid_idp_entry_url(idp_entry_url):
    try:
        is_valid = 'loginToRp' in parse.parse_qs(parse.urlparse(idp_entry_url).query)
        return is_valid
    except URLError:
        return False


@profile.command('ls')
def ls():
    """List all profiles"""

    ls_profiles()


@profile.command('show')
@click.argument('profile-names', nargs=-1)
def show(profile_names):
    """Show details about profile(s)"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    aws_adfs_profiles = aws_adfs_conf['profiles']
    exit_if_no_profile(aws_adfs_conf)
    wrong_profile_names = list()
    for name in profile_names:
        if name in aws_adfs_profiles.keys():
            click.secho('Details of profile ' + name, fg='green')
            click.echo(
                '\n'.join(
                    map(
                        lambda x: '  ' + str(x[0]) + ':  ' + str(x[1]),
                        aws_adfs_profiles[name].items()
                    )
                )
            )
        else:
            wrong_profile_names.append(name)
    ls_profiles_if_profile_names_are_wrong(wrong_profile_names)


@profile.command('create')
def create():
    """Create a profile"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    aws_adfs_profiles = aws_adfs_conf['profiles']
    click.secho('Creating profile, press "Ctrl + C" to abort', fg='yellow')
    profile_name = click.prompt('Profile Name')
    if profile_name in aws_adfs_profiles.keys():
        click.secho(
            'Profile {} has been created'.format(profile_name),
            fg='red'
        )
        click.echo('You can update it or try to create a new one.')
        sys.exit(-1)
    aws_adfs_profiles[profile_name] = dict()
    while True:
        idp_entry_url = click.prompt('IDP Entry Url')
        if is_valid_idp_entry_url(idp_entry_url):
            break
        click.secho('Invalid IDP entry url!', fg='red')
    aws_adfs_profiles[profile_name]['idp_entry_url'] = idp_entry_url
    aws_adfs_profiles[profile_name]['idp_username'] = click.prompt(
        'IDP Username'
    )
    aws_adfs_profiles[profile_name]['idp_role_arn'] = click.prompt(
        'IDP Role ARN'
    )
    aws_adfs_profiles[profile_name]['idp_session_duration'] = click.prompt(
        'IDP Session Duration(in seconds)',
        default=DEFAULT_IDP_SESSION_DURATION,
        type=int
    )
    aws_adfs_profiles[profile_name]['region'] = click.prompt(
        'AWS Region'
    )
    aws_adfs_profiles[profile_name]['output_format'] = click.prompt(
        'Output Format',
        default=DEFAULT_OUTPUT_FORMAT
    )
    save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)
    click.secho('Done.', fg='green')


@profile.command('update')
@click.argument('profile-names', nargs=-1)
def update(profile_names):
    """Update profile(s)"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    exit_if_no_profile(aws_adfs_conf)
    aws_adfs_profiles = aws_adfs_conf['profiles']
    default_profile = aws_adfs_conf['default-profile']
    exit_if_no_profile_is_provided(profile_names, default_profile)
    profile_names = profile_names or [default_profile]
    wrong_profile_names = list()
    succeed_updates = list()
    for profile_name in profile_names:
        if profile_name not in aws_adfs_profiles.keys():
            wrong_profile_names.append(profile_name)
            continue
        click.secho('Updating profile: "{}", '
            'press "Ctrl + C" to abort'.format(profile_name), fg='yellow')
        while True:
            idp_entry_url = click.prompt(
                'IDP Entry Url',
                default=aws_adfs_profiles[profile_name]['idp_entry_url']
            )
            if is_valid_idp_entry_url(idp_entry_url):
                break
            click.secho('Invalid IDP entry url!', fg='red')
        aws_adfs_profiles[profile_name]['idp_entry_url'] = idp_entry_url
        aws_adfs_profiles[profile_name]['idp_username'] = click.prompt(
            'IDP Username',
            default=aws_adfs_profiles[profile_name]['idp_username']
        )
        aws_adfs_profiles[profile_name]['idp_role_arn'] = click.prompt(
            'IDP Role ARN',
            default=aws_adfs_profiles[profile_name]['idp_role_arn']
        )
        aws_adfs_profiles[profile_name]['idp_session_duration'] = click.prompt(
            'IDP Session Duration(in seconds)',
            default=aws_adfs_profiles[profile_name]['idp_session_duration'],
            type=int
        )
        aws_adfs_profiles[profile_name]['region'] = click.prompt(
            'AWS Region',
            default=aws_adfs_profiles[profile_name]['region']
        )
        aws_adfs_profiles[profile_name]['output_format'] = click.prompt(
            'Output Format',
            default=aws_adfs_profiles[profile_name]['output_format']
        )
        save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)
        succeed_updates.append(profile_name)

    if succeed_updates:
        click.secho(
            'Profile(s) "{}" {} been updated'.format(
                '", "'.join(succeed_updates),
                'has' if len(succeed_updates) > 1 else 'have'
            ),
            fg='green'
        )
    ls_profiles_if_profile_names_are_wrong(wrong_profile_names)


@profile.command('delete')
@click.argument('profile-names', nargs=-1)
def delete(profile_names):
    """Delete profile(s)"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    exit_if_no_profile(aws_adfs_conf)
    aws_adfs_profiles = aws_adfs_conf['profiles']
    default_profile = aws_adfs_conf['default-profile']
    exit_if_no_profile_is_provided(profile_names, default_profile)
    profile_names = profile_names or [default_profile]
    sure_to_delete = click.confirm(
        'Are you sure you want to delete profile(s): "{}"'.format(
            '", "'.join(profile_names)
        )
    )
    if not sure_to_delete:
        click.secho('Aborted!', fg='yellow')
        sys.exit(0)
    wrong_profile_names = list()
    deleted_profile_names = list()
    for profile_name in profile_names:
        if profile_name not in aws_adfs_profiles.keys():
            wrong_profile_names.append(profile_name)
            continue

        # delete profile in aws-adfs config file
        del aws_adfs_profiles[profile_name]
        if aws_adfs_conf.get('default-profile') == profile_name:
            del aws_adfs_conf['default-profile']
        save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)
        deleted_profile_names.append(profile_name)

        # delete profile in aws credentials file
        aws_credentials = read_aws_credentials(AWS_CREDENTIALS_FILE)
        aws_credentials.read(AWS_CREDENTIALS_FILE)
        if aws_credentials.has_section(profile_name):
            del aws_credentials[profile_name]
        save_aws_credentials(AWS_CREDENTIALS_FILE, aws_credentials)

        # delete profile in aws config file
        aws_config = read_aws_config(AWS_CONFIG_FILE)
        if aws_config.has_section(profile_name):
            del aws_config[profile_name]
        save_aws_config(AWS_CONFIG_FILE, aws_config)

    if deleted_profile_names:
        click.secho(
            'Profile(s) "{}" {} been deleted.'.format(
                '", "'.join(deleted_profile_names),
                'has' if deleted_profile_names else 'have'
            )
        )
    ls_profiles_if_profile_names_are_wrong(wrong_profile_names)


@profile.command('default')
@click.argument('profile-name', required=False)
def default(profile_name):
    """Show or set the default profile"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    exit_if_no_profile(aws_adfs_conf)
    aws_adfs_profiles = aws_adfs_conf['profiles']
    default_profile = aws_adfs_conf['default-profile']
    exit_if_no_profile_is_provided(profile_name, default_profile)
    if not profile_name:
        click.echo('Your default profile is: "{}"'.format(default_profile))
        return

    if profile_name not in aws_adfs_profiles.keys():
        click.secho('Wrong profile name!', fg='red')
        ls_profiles()
        sys.exit(-1)

    # set default profile in adfs config file
    aws_adfs_conf['default-profile'] = profile_name
    save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)

    # set default profile in aws credentials file
    aws_credentials = read_aws_credentials(AWS_CREDENTIALS_FILE)
    if aws_credentials.has_section(profile_name):
        aws_credentials['default'] = aws_credentials[profile_name]
    save_aws_credentials(AWS_CREDENTIALS_FILE, aws_credentials)

    # set default profile in aws config file
    aws_config = read_aws_config(AWS_CONFIG_FILE)
    if aws_config.has_section(profile_name):
        aws_config['default'] = aws_config[profile_name]
    save_aws_config(AWS_CONFIG_FILE, aws_config)

    click.secho('Done.', fg='green')


@profile.command('expire-at')
@click.argument('profile-names', nargs=-1)
def expire_at(profile_names):
    """Show the expire time of profile(s)"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    exit_if_no_profile(aws_adfs_conf)
    default_profile = aws_adfs_conf['default-profile']
    exit_if_no_profile_is_provided(profile_names, default_profile)
    profile_names = profile_names or [default_profile]
    aws_credentials = read_aws_credentials(AWS_CREDENTIALS_FILE)
    wrong_profile_names = list()
    for profile_name in profile_names:
        if profile_name not in aws_adfs_conf['profiles']:
            wrong_profile_names.append(profile_name)
        elif aws_credentials.has_section(profile_name):
            expire_time = aws_credentials[profile_name].get('expire-at')
            if expire_time:
                click.echo(
                    'Profile "{}" expires at "{}".'.format(
                        profile_name,
                        expire_time
                    )
                )
            else:
                click.echo(
                    'Expire time of profile "{}" is not recorded'.format(
                        profile_name
                    )
                )
        else:
            click.echo(
                'You never logged in with profile: "{}"'.format(
                    profile_name
                )
            )
    ls_profiles_if_profile_names_are_wrong(wrong_profile_names)


# login part


@click.group()
def login_cli():
    pass


@login_cli.command('login')
@click.option('--save-password', flag_value=True, default=False)
@click.argument('profile-names', required=False, nargs=-1)
def login(save_password, profile_names):
    """Login with profile(s)"""

    aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
    exit_if_no_profile(aws_adfs_conf)
    default_profile = aws_adfs_conf['default-profile']
    profiles = aws_adfs_conf['profiles']
    exit_if_no_profile_is_provided(profile_names, default_profile)

    grouped_profiles = dict()
    wrong_profile_names = list()
    profile_names = profile_names or [default_profile]
    for profile_name in profile_names:
        if profile_name not in aws_adfs_conf['profiles']:
            wrong_profile_names.append(profile_name)
            continue
        profile = profiles[profile_name]
        key = (
            profile['idp_entry_url'],
            profile['idp_username']
        )
        if key not in grouped_profiles:
            grouped_profiles[key] = dict()
        grouped_profiles[key][profile_name] = profile

    for key, profiles in grouped_profiles.items():
        adfs_login(profiles, *key, save_password)

    ls_profiles_if_profile_names_are_wrong(wrong_profile_names)


@click.group()
def version_cli():
    pass


@version_cli.command('version')
def show_version():
    """Display the version of this tool"""

    click.echo('v{}'.format(__version__))


cli = click.CommandCollection(sources=[profile_cli, login_cli, version_cli])


if __name__ == '__main__':
    cli()

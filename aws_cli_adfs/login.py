import base64
from datetime import datetime
import json
import re
from urllib.parse import urlparse

import boto.sts
from bs4 import BeautifulSoup
import click
import requests
from requests.exceptions import RequestException
from xml.etree import ElementTree

from .constants import *
from .exceptions import *
from .log import create_logger
from .utils import *


logger = create_logger()


def search_for_principal_arn(_profile, root):

    idp_principal_arn = ''
    aws_roles = list()
    for saml2attribute in root.iter(
        '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
    ):
        saml_role_url = 'https://aws.amazon.com/SAML/Attributes/Role'
        if saml2attribute.get('Name') == saml_role_url:
            for saml2attributevalue in saml2attribute.iter(
                '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
            ):
                chunks = saml2attributevalue.text.split(',')
                principal_arn = chunks[0]
                role_arn = chunks[1]

                if _profile['idp_role_arn'] == role_arn:
                    idp_principal_arn = principal_arn
                    break
                aws_roles.append(role_arn)
    return idp_principal_arn, aws_roles


def get_assertion(
        profiles,
        idp_entry_url,
        idp_username,
        save_password,
        from_saved_password=False
):

    session = requests.Session()
    start_resp = session.get(idp_entry_url, verify=True)
    start_soup = BeautifulSoup(start_resp.text, 'html.parser')
    login_url = start_resp.url
    for input_tag in start_soup.find_all(re.compile('(FORM|form)')):
        action = input_tag.get('action')
        login_id = input_tag.get('id')
        if action and login_id == 'loginForm':
            parsed_url = urlparse(idp_entry_url)
            login_url = '{}://{}{}'.format(
                parsed_url.scheme,
                parsed_url.netloc,
                action
            )
    login_payload = dict()
    password = ''
    for _profile in profiles.values():
        password = _profile.get('password')
        if password:
            break
    if not password or from_saved_password:
        password = click.prompt(
            'Password',
            hide_input=True
        )
        from_saved_password = False
    else:
        from_saved_password = True
    for input_tag in start_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        if 'user' in name.lower() or 'email' in name.lower():
            login_payload[name] = idp_username
        elif 'pass' in name.lower():
            login_payload[name] = password
        else:
            login_payload[name] = value
    login_payload['AuthMethod'] = 'FormsAuthentication'
    login_resp = session.post(
        login_url,
        data=login_payload,
        verify=True
    )
    mfa_url = login_resp.url
    login_soup = BeautifulSoup(login_resp.text, 'html.parser')
    mfa_payload = dict()
    for input_tag in login_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        mfa_payload[name] = value

    if 'ChallengeQuestionAnswer' in mfa_payload:
        if save_password:
            aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
            for profile_name in profiles.keys():
                aws_adfs_conf['profiles'][profile_name]['password'] = password
            save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)
        mfa_code = click.prompt('MFA Code')
        mfa_payload['ChallengeQuestionAnswer'] = mfa_code
        mfa_payload['AuthMethod'] = 'TOTPAuthenticationProvider'
    elif from_saved_password:
        click.secho('The password you have saved is invalid now!', fg='red')
        aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
        for profile_name in profiles.keys():
            if aws_adfs_conf['profiles'][profile_name].get('password'):
                del aws_adfs_conf['profiles'][profile_name]['password']
        save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)
        return get_assertion(
            profiles,
            idp_entry_url,
            idp_username,
            True,
            True
        )
    else:
        raise WrongPasswordException()

    mfa_resp = session.post(
        mfa_url,
        data=mfa_payload,
        verify=True
    )
    mfa_soup = BeautifulSoup(mfa_resp.text, 'html.parser')
    mfa_payload2 = dict()
    for input_tag in mfa_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        mfa_payload2[name] = value

    mfa_payload2['ChallengeQuestionAnswer'] = mfa_code
    mfa_payload2['AuthMethod'] = 'TOTPAuthenticationProvider'

    assertion = mfa_payload2.get('SAMLResponse', '')
    if assertion == '':
        mfa_resp2 = session.post(
            mfa_url,
            data=mfa_payload2,
            verify=True
        )

        soup = BeautifulSoup(mfa_resp2.text, 'html.parser')
        assertion = ''

        for input_tag in soup.find_all('input'):
            if input_tag.get('name') == 'SAMLResponse':
                assertion = input_tag.get('value')
    if not assertion:
        raise WrongMFACodeException()
    return assertion


def parse_assertion(profiles, assertion):

    root = ElementTree.fromstring(base64.b64decode(assertion))
    aws_roles = list()
    denied_roles = list()
    allowed_roles = list()
    token = ''
    for profile_name, _profile in profiles.items():
        aws_credentials = read_aws_credentials(AWS_CREDENTIALS_FILE)
        aws_config = read_aws_config(AWS_CONFIG_FILE)

        idp_principal_arn, aws_roles = search_for_principal_arn(_profile, root)

        if not idp_principal_arn:
            denied_roles.append((profile_name, _profile['idp_role_arn']))
            continue

        conn = boto.sts.connect_to_region(
            _profile['region'],
            profile_name='default'
        )
        token = conn.assume_role_with_saml(
            _profile['idp_role_arn'],
            idp_principal_arn,
            assertion,
            None,
            _profile['idp_session_duration']
        )
        aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
        default_profile = aws_adfs_conf['default-profile']
        _profiles_with_default = [profile_name]
        if profile_name == default_profile:
            _profiles_with_default.append('default')
        for __profile in _profiles_with_default:
            if not aws_credentials.has_section(__profile):
                aws_credentials.add_section(__profile)
            aws_credentials.set(
                __profile,
                'aws_access_key_id',
                token.credentials.access_key
            )
            aws_credentials.set(
                __profile,
                'aws_secret_access_key',
                token.credentials.secret_key
            )
            aws_credentials.set(
                __profile,
                'aws_session_token',
                token.credentials.session_token
            )
            aws_credentials.set(
                __profile,
                'expiration',
                token.credentials.expiration
            )
            aws_credentials.set(
                __profile,
                'region',
                token.credentials.expiration
            )
            aws_credentials.set(
                __profile,
                'region',
                _profile['region']
            )
            if not aws_config.has_section(__profile):
                aws_config.add_section(__profile)
            aws_config.set(
                __profile,
                'region',
                _profile['region']
            )

        save_aws_credentials(AWS_CREDENTIALS_FILE, aws_credentials)
        save_aws_config(AWS_CONFIG_FILE, aws_config)
        allowed_roles.append((profile_name, _profile['idp_role_arn']))

    return aws_roles, denied_roles, allowed_roles, token


def login(
        profiles,
        idp_entry_url,
        idp_username,
        save_password=False
):

    click.echo('Hello, {}！'.format(idp_username))
    click.echo(
        'Login with profile(s): "{}"'.format(
            '", "'.join(profiles.keys())
        )
    )
    result = dict()
    result['profiles'] = list(profiles.keys())
    result['timestamp'] = datetime.now().timestamp()
    result['action'] = 'login'
    try:
        assertion = get_assertion(
            profiles,
            idp_entry_url,
            idp_username,
            save_password
        )
    except WrongPasswordException:
        click.secho('Wrong password!', fg='red')
        click.echo('(If you login too often,'
                   ' ADFS server will reject your request,'
                   ' and return this message too)')
        result['result'] = 'failed'
        result['reason'] = 'wrong password'
    except WrongMFACodeException:
        click.secho('Wrong MFA code!', fg='red')
        result['result'] = 'failed'
        result['reason'] = 'wrong mfa code'
    except RequestException:
        click.secho(
            'Your IDP entry is unreachable!',
            fg='yellow'
        )
        click.secho(
            'Entry url: {}'.format(
                list(profiles.values())[0]['idp_entry_url']
            ),
            fg='yellow'
        )
        result['result'] = 'failed'
        result['reason'] = 'network problem'
    else:
        (
            aws_roles,
            denied_roles,
            allowed_roles,
            token
        ) = parse_assertion(profiles, assertion)

        if allowed_roles:
            for role in allowed_roles:
                click.echo('With profile(s): "{}"'.format(role[0]))
                click.secho('Login succeed!', fg='green')
                click.echo(
                    'Your AKSK will expire at "{}"'.format(
                        token.credentials.expiration
                    )
                )

        if denied_roles:
            for role in denied_roles:
                click.echo('On profile "{}"'.format(role[0]))
                click.secho(
                    'You are not allowed to assume role: "{}"'.format(
                        role[1]
                    ),
                    fg='red'
                )

            click.echo('The roles you are allowed to assume are:')
            for aws_role in aws_roles:
                click.echo('  -  ' + aws_role)
        result['result'] = 'succeed'
    finally:
        logger.info(json.dumps(result))

import base64
from datetime import datetime
import json
import re
from urllib import parse

import boto.sts
from bs4 import BeautifulSoup
import click
import requests
from requests.exceptions import RequestException
from xml.etree import ElementTree

from .constants import *
from .exceptions import *
from .log import logger
from .utils import *


def search_for_principal_arn(profile, root):
    """search for principle arn"""

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

                if profile['idp_role_arn'] == role_arn:
                    idp_principal_arn = principal_arn
                    break
                aws_roles.append(role_arn)
    return idp_principal_arn, aws_roles


def get_saml_resp(profiles, idp_entry_url, idp_username, save_password):
    """get saml response"""

    session = requests.Session()

    # idp entry
    entry_resp = session.get(idp_entry_url, verify=True)
    entry_soup = BeautifulSoup(entry_resp.text, 'html.parser')

    # login
    login_url = entry_resp.url
    for input_tag in entry_soup.find_all(re.compile('(FORM|form)')):
        action = input_tag.get('action')
        login_id = input_tag.get('id')
        if action and login_id in ('loginForm', 'idpForm'):
            parsed_url = parse.urlparse(idp_entry_url)
            login_url = '{}://{}{}'.format(
                parsed_url.scheme,
                parsed_url.netloc,
                action
            )

    # get password
    login_payload = dict()
    password_keyname = ''
    for input_tag in entry_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        if 'user' in name.lower() or 'email' in name.lower():
            login_payload[name] = idp_username
        elif 'pass' in name.lower():
            password_keyname = name
            login_payload[name] = ''
        else:
            login_payload[name] = value
    if not any(['pass' in key.lower() for key in login_payload.keys()]):
        raise WrongIDPEntryUrlException()
    for profile in profiles.values():
        password = profile.get('password')
        if password:
            break
    if not password:
        password = click.prompt('Password', hide_input=True)
        from_saved_password = False
    else:
        from_saved_password = True
    login_payload[password_keyname] = password

    # send the login request
    login_resp = session.post(
        login_url,
        data=login_payload,
        verify=True
    )
    login_soup = BeautifulSoup(login_resp.text, 'html.parser')
    login_resp_form = dict()
    for input_tag in login_soup.find_all(re.compile('(INPUT|input)')):
        name = input_tag.get('name', '')
        value = input_tag.get('value', '')
        login_resp_form[name] = value

    # wrong password
    if any(['pass' in key for key in map(
            lambda x: x.lower(),
            login_resp_form.keys()
    )]):
        if from_saved_password:
            click.secho(
                'The password you have saved is invalid now!',
                fg='red'
            )
            aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
            for profile_name, profile in profiles.items():
                if profile.get('password'):
                    del profiles[profile_name]['password']
                if aws_adfs_conf['profiles'][profile_name].get('password'):
                    del aws_adfs_conf['profiles'][profile_name]['password']
            save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)
            return get_saml_resp(
                profiles,
                idp_entry_url,
                idp_username,
                True
            )
        else:
            raise WrongPasswordException()

    # save password
    if save_password:
        aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
        for profile_name in profiles.keys():
            aws_adfs_conf['profiles'][profile_name]['password'] = password
        save_aws_adfs_config(AWS_ADFS_CONFIG_FILE, aws_adfs_conf)

    if 'SAMLResponse' in login_resp_form:
        saml_resp = login_resp_form['SAMLResponse']
    # if mfa is enabled
    else:
        mfa_url = login_resp.url
        for input_tag in login_soup.find_all(re.compile('(FORM|form)')):
            action = input_tag.get('action')
            login_id = input_tag.get('id')
            if action and login_id.lower() in ('loginform', 'idpform'):
                parsed_url = parse.urlparse(idp_entry_url)
                mfa_url = '{}://{}{}'.format(
                    parsed_url.scheme,
                    parsed_url.netloc,
                    action
                )
                
        mfa_payload = login_resp_form
        # if using mfa code
        if 'ChallengeQuestionAnswer' in mfa_payload:
            mfa_code = click.prompt('MFA Code')
            mfa_payload['ChallengeQuestionAnswer'] = mfa_code
        elif 'AuthMethod' in mfa_payload:
            click.secho(
                'A notification has been sent to your mobile device.'
                ' Please respond to continue',
                fg='yellow'
            )
        else:
            raise WrongRelyingPartyException()

        # send the mfa request
        mfa_resp = session.post(
            mfa_url,
            data=mfa_payload,
            verify=True
        )
        mfa_soup = BeautifulSoup(mfa_resp.text, 'html.parser')
        for input_tag in mfa_soup.find_all(re.compile('(INPUT|input)')):
            if input_tag.get('name') == 'SAMLResponse':
                saml_resp = input_tag.get('value')
                break
        else:
            if 'ChallengeQuestionAnswer' in mfa_payload:
                raise WrongMFACodeException()
            elif 'AuthMethod' in mfa_payload:
                raise LoginNotApprovedException

    return saml_resp


def parse_saml_resp(profiles, saml_resp):
    """parse saml response"""

    root = ElementTree.fromstring(base64.b64decode(saml_resp))
    aws_roles = list()
    denied_roles = list()
    allowed_roles = list()
    token = ''
    aws_credentials = read_aws_credentials(AWS_CREDENTIALS_FILE)
    aws_config = read_aws_config(AWS_CONFIG_FILE)
    for profile_name, profile in profiles.items():
        idp_principal_arn, aws_roles = search_for_principal_arn(profile, root)
        if not idp_principal_arn:
            denied_roles.append((profile_name, profile['idp_role_arn']))
            continue
        allowed_roles.append((profile_name, profile['idp_role_arn']))
        conn = boto.sts.connect_to_region(
            profile['region'],
            profile_name='default'
        )
        if not conn:
            if profile['region'].startswith('cn-'):
                region = 'cn-north-1'
            elif profile['region'].startswith('eu-'):
                region = 'eu-west-1'
            elif profile['region'].startswith('us-'):
                region = 'us-east-1'
            elif profile['region'].startswith('ap-'):
                region = 'ap-southeast-1'
            else:
                region = 'eu-west-1'
            conn = boto.sts.connect_to_region(
                region,
                profile_name='default'
            )
            if not conn:
                raise WrongAWSRegionException(profile['region'])
        token = conn.assume_role_with_saml(
            profile['idp_role_arn'],
            idp_principal_arn,
            saml_resp,
            None,
            profile['idp_session_duration']
        )
        aws_adfs_conf = read_aws_adfs_config(AWS_ADFS_CONFIG_FILE)
        default_profile = aws_adfs_conf['default-profile']
        profiles_with_default = [profile_name]
        if profile_name == default_profile:
            profiles_with_default.append('default')
        for profile_ in profiles_with_default:
            if not aws_credentials.has_section(profile_):
                aws_credentials.add_section(profile_)
            aws_credentials.set(
                profile_,
                'aws_access_key_id',
                token.credentials.access_key
            )
            aws_credentials.set(
                profile_,
                'aws_secret_access_key',
                token.credentials.secret_key
            )
            aws_credentials.set(
                profile_,
                'aws_session_token',
                token.credentials.session_token
            )
            aws_credentials.set(
                profile_,
                'expire-at',
                token.credentials.expiration
            )
            aws_credentials.set(
                profile_,
                'region',
                token.credentials.expiration
            )
            aws_credentials.set(profile_, 'region', profile['region'])
            if not aws_config.has_section(profile_):
                aws_config.add_section(profile_)
            aws_config.set(profile_, 'region', profile['region'])

    save_aws_credentials(AWS_CREDENTIALS_FILE, aws_credentials)
    save_aws_config(AWS_CONFIG_FILE, aws_config)

    return aws_roles, denied_roles, allowed_roles, token


def adfs_login(profiles, idp_entry_url, idp_username, save_password=False):
    """login the adfs server"""

    click.echo('Hello, {}！'.format(idp_username))
    click.echo(
        'You are logging in with profile(s): "{}"'.format(
            '", "'.join(profiles.keys())
        )
    )
    result = dict()
    result['profiles'] = list(profiles.keys())
    result['timestamp'] = datetime.now().timestamp()
    result['action'] = 'login'
    try:
        saml_resp = get_saml_resp(
            profiles,
            idp_entry_url,
            idp_username,
            save_password
        )
        (
            aws_roles,
            denied_roles,
            allowed_roles,
            token
        ) = parse_saml_resp(profiles, saml_resp)
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
    except LoginNotApprovedException:
        click.secho('Login is not approved!', fg='red')
        result['result'] = 'failed'
        result['reason'] = 'login not approved'
    except WrongIDPEntryUrlException:
        click.secho('Wrong IDP entry url -> {}'.format(idp_entry_url), fg='red')
        result['result'] = 'failed'
        result['reason'] = 'wrong IDP entry url'
    except WrongRelyingPartyException:
        click.secho(
            'Wrong relying party -> {}'.format(
                parse.parse_qs(
                    parse.urlparse(idp_entry_url).query
                ).get('loginToRp', [''])[0]
            ),
            fg='red'
        )
        click.secho('in entry url -> {}'.format(idp_entry_url), fg='red')
        result['result'] = 'failed'
        result['reason'] = 'wrong relying party'
    except WrongAWSRegionException:
        click.secho('Either the region does not exist or AWS STS is not enabled in this region!', fg='red')
    except RequestException:
        click.secho('Your IDP entry is unreachable!', fg='red')
        click.secho('Entry url -> {}'.format(idp_entry_url), fg='yellow')
        result['result'] = 'failed'
        result['reason'] = 'idp entry is unreachable'
    else:
        if allowed_roles:
            for role in allowed_roles:
                click.echo('With profile(s): "{}"'.format(role[0]))
                click.secho('Login successful!', fg='green')
                click.echo('Your AKSK will expire at "{}"'
                           .format(token.credentials.expiration))
        if denied_roles:
            for role in denied_roles:
                click.echo('With profile "{}"'.format(role[0]))
                click.secho('You are not allowed to assume role: "{}"'
                            .format(role[1]), fg='red')

            click.echo('The roles you are allowed to assume are:')
            for aws_role in aws_roles:
                click.echo('  -  ' + aws_role)
        result['result'] = 'successful'
    finally:
        logger.info(json.dumps(result))

import boto.exception
import boto.sts
import codecs
from xml.etree import ElementTree
from bs4 import BeautifulSoup
import os
import configparser
import requests
import re


AWS_CREDENTIALS_PATH = '~/.aws/credentials'
OPENAM_SEARCH_STRING = 'XUI/#login/&'


def write_aws_credentials(profile, key_id, secret, session_token=None):
    credentials_path = os.path.expanduser(AWS_CREDENTIALS_PATH)
    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    config = configparser.ConfigParser()
    if os.path.exists(credentials_path):
        config.read(credentials_path)

    config[profile] = {}
    config[profile]['aws_access_key_id'] = key_id
    config[profile]['aws_secret_access_key'] = secret
    if session_token:
        # apparently the different AWS SDKs either use "session_token" or "security_token", so set both
        config[profile]['aws_session_token'] = session_token
        config[profile]['aws_security_token'] = session_token

    with open(credentials_path, 'w') as fd:
        config.write(fd)


def get_saml_response(html: str):
    """
    Parse SAMLResponse from FS page
    >>> get_saml_response('<input name="a"/>')
    >>> get_saml_response('<body xmlns="bla"><form><input name="SAMLResponse" value="eG1s"/></form></body>')
    'xml'
    """
    soup = BeautifulSoup(html, "html.parser")

    for elem in soup.find_all('input', attrs={'name': 'SAMLResponse'}):
        saml_base64 = elem.get('value')
        xml = codecs.decode(saml_base64.encode('ascii'), 'base64').decode('utf-8')
        return xml


def get_form_action(html: str):
    '''
    >>> get_form_action('<body><form action="test"></form></body>')
    'test'
    '''
    soup = BeautifulSoup(html, "html.parser")
    return soup.find('form').get('action')


def get_form_xsrf(html: str):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find('input', {'name': '_xsrf'})['value']


def get_account_name(role_arn: str, account_names: dict):
    number = role_arn.split(':')[4]
    if account_names:
        return account_names.get(number)


def get_roles(saml_xml: str) -> list:
    """
    Extract SAML roles from SAML assertion XML

    >>> get_roles('''<xml xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Assertion>
    ... <Attribute FriendlyName="Role" Name="https://aws.amazon.com/SAML/Attributes/Role">
    ... <AttributeValue>arn:aws:iam::123:role/<ROLE_NAME>,arn:aws:iam::123:saml-provider/SAMLProvider</AttributeValue>
    ... </Attribute>
    ... </Assertion></xml>''')
    [(arn:aws:iam::123:role/<ROLE_NAME>', 'arn:aws:iam::123:saml-provider/SAMLProvider')]
    """
    tree = ElementTree.fromstring(saml_xml)

    assertion = tree.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')

    roles = []
    for attribute in assertion.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name]'):
        if attribute.attrib['Name'] == 'https://aws.amazon.com/SAML/Attributes/Role':
            for val in attribute.findall('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                role_arn, provider_arn = val.text.split(',')
                roles.append((role_arn, provider_arn))
    return roles


def get_account_names(html: str) -> dict:
    '''
    Parse account names from AWS page

    >>> get_account_names('')
    {}

    >>> get_account_names('<div class="saml-account-name">Account: blub  (123) </div>')
    {'123': 'blub'}

    >>> get_account_names('<div class="saml-account-name">Account: blub  123) </div>')
    {}
    '''
    soup = BeautifulSoup(html, "html.parser")

    accounts = {}
    for elem in soup.find_all('div', attrs={'class': 'saml-account-name'}):
        try:
            name_number = elem.text.split(':', 1)[-1].strip().rstrip(')')
            name, number = name_number.rsplit('(', 1)
            name = name.strip()
            number = number.strip()
            accounts[number] = name
        except Exception:
            # just skip account in case of parsing errors
            pass
    return accounts


class AuthenticationFailed(Exception):
    def __init__(self):
        pass


class AssumeRoleFailed(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Assuming role failed: {}'.format(self.msg)


def authenticate(url, user, password):
    '''Authenticate against the provided Identity Provider'''

    session = requests.Session()
    response = session.get(url)
    provider = ''

    if re.match('.*ann\.com', url) is not None:
        provider = 'cc-us'
        relying_party = '1900aa23-cb5a-4a45-8ad0-968d229e955f'
    if re.match('.*ann\.com.*cn', url) is not None:
        provider = 'cc-cn'
        relying_party = '43a05b4e-c29f-4f99-822c-0ff6364b6ce4'
    if re.match('.*jumpcloud\.com', url) is not None:
        provider = 'jumpcloud'

    if re.match('cc.*', provider):
        data = {
            'SignInOtherSite': 'SignInOtherSite',
            'RelyingParty': relying_party,
            'SignInSubmit': 'Sign in',
            'SingleSignOut': 'SingleSignOut',
            'AuthMethod': 'FormsAuthentication',
            'UserName': user,
            'Password': password,
        }
    elif provider == 'jumpcloud':
        # NOTE: parameters are hardcoded for JumpCloud IDP
        data = {
          'context':'sso',
          'otp':'',
          'pathTo': '',
          'redirectTo':'saml2/aws',
          'email': user,
          'password': password,
          '_xsrf': get_form_xsrf(response.text)
        }
    else:
        # Check if OpenAM is the IdP
        if OPENAM_SEARCH_STRING in response.url:
            server_info_url = response.url[:response.url.index(OPENAM_SEARCH_STRING)] + 'json/serverinfo/*'
            openam_url = response.url.replace(OPENAM_SEARCH_STRING, 'json/authenticate?', 1)

            # Get cookie name
            response = session.get(server_info_url)
            cookie_name = response.json()['cookieName']

            # Get login form
            response = session.post(openam_url)
            login_form = response.json()

            # Submit authentication credentials
            for item in login_form['callbacks']:
                if item['type'] == 'NameCallback':
                    item['input'][0]['value'] = user
                if item['type'] == 'PasswordCallback':
                    item['input'][0]['value'] = password

            response2 = session.post(openam_url, json=login_form)

            # Ask for second factor authentication, if necessary
            if 'stage' in response2.json():
                otp_form = response2.json()

                otp_code = input('Submit OTP code: ')
                for item in otp_form['callbacks']:
                    if item['type'] == 'PasswordCallback':
                        item['input'][0]['value'] = otp_code

                response2 = session.post(openam_url, json=otp_form)

            if response2.status_code != 200:
                raise AuthenticationFailed()

            # Set cookie for SAML response
            session.cookies.set(cookie_name, response2.json()['tokenId'])

            response2 = session.get(response2.json()['successUrl'])
        else:

            # NOTE: parameters are hardcoded for Shibboleth IDP
            data = {'j_username': user, 'j_password': password, 'submit': 'Login'}
            response2 = session.post(response.url, data=data)

    if provider == 'jumpcloud':
        response2 = session.post('https://sso.jumpcloud.com/auth', data=data)
    else:
        response2 = session.post(response.url, data=data)

    saml_xml = get_saml_response(response2.text)
    if not saml_xml:
        raise AuthenticationFailed()

    url = get_form_action(response2.text)
    encoded_xml = codecs.encode(saml_xml.encode('utf-8'), 'base64')
    response3 = session.post(url, data={'SAMLResponse': encoded_xml})
    account_names = get_account_names(response3.text)

    roles = get_roles(saml_xml)

    if provider == 'jumpcloud':
        roles = [(p_arn, r_arn, get_account_name(r_arn, account_names)) for r_arn, p_arn in roles]
    else:
        roles = [(p_arn, r_arn, get_account_name(r_arn, account_names)) for p_arn, r_arn in roles]

    return saml_xml, roles


def assume_role(saml_xml, role_arn, provider_arn):
    saml_assertion = codecs.encode(saml_xml.encode('utf-8'), 'base64').decode('ascii').replace('\n', '')

    # boto NEEDS some credentials, but does not care about their actual values
    os.environ['AWS_ACCESS_KEY_ID'] = 'fake123'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'fake123'

    try:
        conn = boto.sts.connect_to_region('us-east-1')
        response_data = conn.assume_role_with_saml(role_arn, provider_arn, saml_assertion)
    except boto.exception.BotoServerError as e:
        raise AssumeRoleFailed(e.message)
    finally:
        del os.environ['AWS_ACCESS_KEY_ID']
        del os.environ['AWS_SECRET_ACCESS_KEY']

    key_id = response_data.credentials.access_key
    secret = response_data.credentials.secret_key
    session_token = response_data.credentials.session_token
    return key_id, secret, session_token

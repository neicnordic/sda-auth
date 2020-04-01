from sda_auth.settings import SERVICE_SETTINGS as config
import requests
import flask
from requests.auth import HTTPBasicAuth
import logging
from oic import rndstr
from oic.oic import Client, RegistrationResponse, AuthorizationResponse, AuthorizationErrorResponse, AccessTokenResponse, Grant, Token
from oic.oic.message import ProviderConfigurationResponse
from oic.utils import time_util
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from werkzeug.utils import redirect

_CLIENT_ID = config['ELIXIR_ID']
_CLIENT_SECRET = config['ELIXIR_SECRET']
_AUTHORISATION_URL = config['ELIXIR_AUTH_URL']
_ACCESS_TOKEN_URL = config['ELIXIR_TOKEN_URL']
_JWKS_URL = config['ELIXIR_CERTS_URL']
_USERINFO_URL = config['ELIXIR_USERINFO_URL']
_ISSUER_URL = config['ELIXIR_ISSUER_URL']
_TOKEN_REVOCATION_URL = config['ELIXIR_REVOCATION_URL']
_ELIXIR_REDIRECT_URL = config['ELIXIR_REDIRECT_URI']
_ELIXIR_SCOPE = config['ELIXIR_SCOPE']


class ElixirAuthenticator:
    """Elixir authentication handler."""

    def __init__(self):
        """Construct a Elixir authenticator class."""
        self.client = self.get_client()

    def get_client(self):
        """Retrieve the cllient for the OIDC auth."""
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

        client_info = {"client_id": _CLIENT_ID,
                       "client_secret": _CLIENT_SECRET}

        client_reg = RegistrationResponse(**client_info)
        client.store_registration_info(client_reg)

        provider_info = {"issuer": _ISSUER_URL,
                         "authorization_endpoint": _AUTHORISATION_URL,
                         "token_endpoint": _ACCESS_TOKEN_URL,
                         "userinfo_endpoint": _USERINFO_URL,
                         "jwks_uri": _JWKS_URL}

        op_info = ProviderConfigurationResponse(**provider_info)
        client.handle_provider_config(op_info, op_info['issuer'])

        return client

    def authenticate(self, interactive=True):
        """Authenticate user."""
        flask.session['destination'] = flask.request.url
        flask.session['state'] = rndstr()
        flask.session['nonce'] = rndstr()

        extra_auth_params = {}
        if not interactive:
            extra_auth_params['prompt'] = 'none'

        login_url = self.send_authentication_request(flask.session['state'],
                                                     flask.session['nonce'],
                                                     extra_auth_params)
        return redirect(login_url)

    def send_authentication_request(self, state, nonce, extra_auth_params):
        """Send user auth request."""
        args = {'response_type': 'code',
                'grant_type': 'authorization_code',
                'scope': _ELIXIR_SCOPE.split(),
                'timeout': '10',
                'redirect_uri': _ELIXIR_REDIRECT_URL,
                'state': state,
                'nonce': nonce}

        logging.debug(f'{_ELIXIR_REDIRECT_URL} is the redir')
        args.update(extra_auth_params)
        auth_request = self.client.construct_AuthorizationRequest(request_args=args,
                                                                  authn_method="client_secret_basic")

        logging.debug('Sending authentication request: %s', auth_request.to_json())
        return auth_request.request(_AUTHORISATION_URL)

    def handle_authentication_response(self):
        """Handle auth response."""
        auth_resp = flask.request.args
        logging.debug('received authentication response')
        authn_resp = self.parse_authentication_response(auth_resp)
        logging.debug('handling authentication response: %s', authn_resp.to_json())
        flask.session['code'] = authn_resp['code']

    def parse_authentication_response(self, response_params):
        """Parse auth response."""
        if 'error' in response_params:
            response = AuthorizationErrorResponse(**response_params)
        else:
            response = AuthorizationResponse(**response_params)
            logging.debug("Verifying key jar")
            response.verify(keyjar=self.client.keyjar)

        assert flask.session['state'] == response['state']
        return response

    def send_token_request(self):
        """Send token request."""
        args = {"response_type": 'access_token',
                "grant_type": 'authorization_code',
                "code": flask.session['code'],
                "scope": _ELIXIR_SCOPE.split()}
        htargs = {'timeout': 10}

        grant = Grant()
        grant.code = flask.session['code']
        grant.grant_expiration_time = time_util.utc_time_sans_frac() + 30
        self.client.grant = {flask.session['state']: grant}
        logging.debug(flask.session.get("code"))
        logging.debug('making token request: %s', args)
        return self.client.do_access_token_request(state=flask.session["state"],
                                                   request_args=args,
                                                   http_args=htargs,
                                                   authn_method="client_secret_basic")

    def handle_token_response(self, resp):
        """Handle token response."""
        logging.debug('handling token response: %s', resp.to_json())
        self.parse_token_response(resp)
        flask.session['access_token'] = resp['access_token']
        return resp

    @staticmethod
    def parse_token_response(response_params):
        """Parse token response."""
        response = AccessTokenResponse(**response_params)
        return response

    def send_userinfo_request(self, token_resp):
        """Send user info request."""
        htargs = {'timeout': 10}
        grant = Grant()
        token = Token(token_resp)
        grant.tokens.append(token)
        self.client.grant[flask.session['state']] = grant
        grant.tokens.append(token)
        userinfo = self.client.do_user_info_request(state=flask.session["state"],
                                                    http_args=htargs)
        return userinfo

    @staticmethod
    def handle_userinfo_response(resp):
        """Handle user info response."""
        logging.debug('handling userinfo response: %s', resp.to_json())
        return resp

    @staticmethod
    def logout_from_elixir():
        """Sign out from Elixir."""
        flask.session.pop("access_token")

    @staticmethod
    def revoke_token():
        """Revoke Elixir auth token."""
        logging.debug('Revoking token...')
        user_session = flask.session
        if user_session.get("access_token", None) is None:
            return None
        else:
            token_payload = {"token": user_session['access_token']}
            response = requests.get(_TOKEN_REVOCATION_URL,
                                    params=token_payload,
                                    auth=HTTPBasicAuth(config["ELIXIR_ID"],
                                                       config["ELIXIR_SECRET"]))
            if response.status_code == 200:
                logging.info("Your token has been successfully revoked")
                return True
            else:
                logging.warning(f'{response.status_code}: {response.content}')
                return None

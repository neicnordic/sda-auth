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


LOG = logging.getLogger("elixir")
LOG.propagate = False


class ElixirAuthenticator:
    """Elixir authentication handler."""

    def __init__(self, id, secret, auth_url, token_url, jwks_url, userinfo_url, issuer_url, rev_url, redirect_url, scope):
        """Construct a Elixir authenticator class."""
        self.id = id
        self.auth_url = auth_url
        self.secret = secret
        self.token_url = token_url
        self.jwks_url = jwks_url
        self.userinfo_url = userinfo_url
        self.issuer_url = issuer_url
        self.rev_url = rev_url
        self.redirect_url = redirect_url
        self.scope = scope
        self.client = self.get_client()

    def get_client(self):
        """Retrieve the cllient for the OIDC auth."""
        client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

        client_info = {"client_id": self.id,
                       "client_secret": self.secret}

        client_reg = RegistrationResponse(**client_info)
        client.store_registration_info(client_reg)

        provider_info = {"issuer": self.issuer_url,
                         "authorization_endpoint": self.auth_url,
                         "token_endpoint": self.token_url,
                         "userinfo_endpoint": self.userinfo_url,
                         "jwks_uri": self.jwks_url}

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
                'scope': self.scope.split(),
                'timeout': '10',
                'redirect_uri': self.redirect_url,
                'state': state,
                'nonce': nonce}

        LOG.debug('%s is the redirect URL', self.redirect_url)
        args.update(extra_auth_params)
        auth_request = self.client.construct_AuthorizationRequest(request_args=args,
                                                                  authn_method="client_secret_basic")

        LOG.debug('Sending authentication request: %s', auth_request.to_json())
        return auth_request.request(self.auth_url)

    def handle_authentication_response(self):
        """Handle auth response."""
        auth_resp = flask.request.args
        authn_resp = self.parse_authentication_response(auth_resp)
        LOG.debug('handling authentication response: %s', authn_resp.to_json())
        flask.session['code'] = authn_resp['code']

    def parse_authentication_response(self, response_params):
        """Parse auth response."""
        if 'error' in response_params:
            response = AuthorizationErrorResponse(**response_params)
        else:
            response = AuthorizationResponse(**response_params)
            LOG.debug("Verifying key jar")
            response.verify(keyjar=self.client.keyjar)

        assert flask.session['state'] == response['state']
        return response

    def send_token_request(self):
        """Send token request."""
        args = {"response_type": 'access_token',
                "grant_type": 'authorization_code',
                "scope": self.scope.split()}
        htargs = {'timeout': 10}

        grant = Grant()
        grant.code = flask.session.pop("code")
        grant.grant_expiration_time = time_util.utc_time_sans_frac() + 30
        self.client.grant = {flask.session['state']: grant}
        LOG.debug('making token request: %s', args)
        return self.client.do_access_token_request(state=flask.session["state"],
                                                   request_args=args,
                                                   http_args=htargs,
                                                   authn_method="client_secret_basic")

    def handle_token_response(self, resp):
        """Handle token response."""
        LOG.debug('handling token response: %s', resp.to_json())
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
        LOG.debug('handling userinfo response: %s', resp.to_json())
        return resp

    @staticmethod
    def logout_from_elixir():
        """Sign out from Elixir."""
        flask.session.pop("access_token")

    def revoke_token(self):
        """Revoke Elixir auth token."""
        LOG.debug('Revoking token...')
        access_token = flask.session.get("access_token", None)
        if access_token is None:
            return None
        else:
            token_payload = {"token": access_token}
            response = requests.get(self.rev_url,
                                    params=token_payload,
                                    auth=HTTPBasicAuth(config["ELIXIR_ID"],
                                                       config["ELIXIR_SECRET"]))
            if response.status_code == 200:
                LOG.info('The token %s has been successfully revoked', access_token)
                return True
            else:
                LOG.warning('Token was not revoked due to: %s : %s', response.status_code, response.content)
                return None

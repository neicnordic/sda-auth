from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata
from settings import SERVICE_SETTINGS as config
import requests
import flask
from flask import redirect
from flask_pyoidc.user_session import UserSession, UninitialisedSession
from requests.auth import HTTPBasicAuth
import logging
from route import app
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc import auth_response_handler
import importlib_resources


_CLIENT_ID = config['ELIXIR_ID']
_CLIENT_SECRET = config['ELIXIR_SECRET']
_AUTHORISATION_URL = config['ELIXIR_AUTH_URL']
_ACCESS_TOKEN_URL = config['ELIXIR_TOKEN_URL']
_JWKS_URL = config['ELIXIR_CERTS_URL']
_USERINFO_URL = config['ELIXIR_USERINFO_URL']
_ISSUER_URL = config['ELIXIR_ISSUER_URL']
_TOKEN_REVOCATION_URL = config['ELIXIR_REVOCATION_URL']
_ELIXIR_SCOPE = config['ELIXIR_SCOPE']

_CLIENT_METADATA = ClientMetadata(client_id=_CLIENT_ID, client_secret=_CLIENT_SECRET)

_PROVIDER_METADATA = ProviderMetadata(issuer=_ISSUER_URL,
                                      authorization_endpoint=_AUTHORISATION_URL,
                                      userinfo_endpoint=_USERINFO_URL,
                                      token_endpoint=_ACCESS_TOKEN_URL,
                                      jwks_uri=_JWKS_URL)

PROVIDER_CONFIG = ProviderConfiguration(provider_metadata=_PROVIDER_METADATA,
                                        client_metadata=_CLIENT_METADATA,
                                        auth_request_params={'scope': _ELIXIR_SCOPE.split()})

oidc_authenticator = OIDCAuthentication({'default': PROVIDER_CONFIG}, app)


def authenticate_with_elixir():
    """Authenticate with Elixir."""
    session = UserSession(flask.session, "default")
    pyoidc_fcd = oidc_authenticator.clients[session.current_provider]

    if session.should_refresh(pyoidc_fcd.session_refresh_interval_seconds):
        logging.debug('Refreshing user auth"')
        return oidc_authenticator._authenticate(client=pyoidc_fcd, interactive=False)
    elif session.is_authenticated():
        logging.debug('User already authenticated')
        return None
    else:
        logging.debug('User not authenticated')
        return oidc_authenticator._authenticate(client=pyoidc_fcd)


def logout_from_elixir():
    """Sign out from Elixir."""
    if 'state' in flask.request.args:
        # returning redirect from provider
        if flask.request.args['state'] != flask.session.pop('end_session_state'):
            logging.error("Got unexpected state '%s' after logout redirect.", flask.request.args['state'])
            return None

    return oidc_authenticator._logout()


def revoke_token():
    """Revoke Elixir auth token."""
    logging.debug('Revoking token...')
    user_session = handle_uninitialised_session()
    if user_session is None:
        return None
    else:
        token_payload = {"token": user_session.access_token}
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


def handle_uninitialised_session():
    """Handle sessions that might not have been initialised."""
    try:
        session = UserSession(flask.session)
        return session
    except UninitialisedSession:
        logging.debug('The user was already logged out')
        return None


def handle_auth_response():
    """Handle auth response to get user info."""
    has_error = flask.request.args.get('error', False, lambda x: bool(int(x)))
    if has_error:
        if 'error' in flask.session:
            logging.error("Error in flask session")
            return "Errpr in flask session"
        logging.error("Auth response could not be handled")
        return 'Something went wrong.'

    if flask.session.pop('fragment_encoded_response', False):
        return importlib_resources.read_binary('flask_pyoidc', 'parse_fragment.html').decode('utf-8')

    is_processing_fragment_encoded_response = flask.request.method == 'POST'

    if is_processing_fragment_encoded_response:
        auth_resp = flask.request.form
    else:
        auth_resp = flask.request.args

    client = oidc_authenticator.clients[UserSession(flask.session).current_provider]

    authn_resp = client.parse_authentication_response(auth_resp)
    logging.debug('Received authentication response: %s', authn_resp.to_json())

    try:
        result = auth_response_handler.AuthResponseHandler(client).process_auth_response(authn_resp,
                                                                                         flask.session.pop('state'),
                                                                                         flask.session.pop('nonce'))
    except auth_response_handler.AuthResponseErrorResponseError as e:
        logging.error(e)
        return 'The authentication response threw an exception'
    except auth_response_handler.AuthResponseProcessError as e:
        logging.error(e)
        return 'The authentication response could not be processed'

    userinfo = result.userinfo_claims

    # Since we cannot store all visas in the session cookie, we pick just one
    if 'ga4gh_passport_v1' in userinfo:
        logging.debug('Passport found in userinfo')
        visa = userinfo['ga4gh_passport_v1'][0]
        userinfo.pop('ga4gh_passport_v1')
        userinfo["visa"] = visa

    UserSession(flask.session).update(result.access_token,
                                      result.id_token_claims,
                                      result.id_token_jwt,
                                      userinfo)

    destination = flask.session.pop('destination')
    if is_processing_fragment_encoded_response:
        return destination

    return redirect(destination, 302)

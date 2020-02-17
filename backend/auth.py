from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata
from settings import SERVICE_SETTINGS as config
import requests
from functools import wraps
import flask
from flask_pyoidc.user_session import UserSession, UninitialisedSession
from requests.auth import HTTPBasicAuth
import logging

_CLIENT_ID = config['ELIXIR_ID']
_CLIENT_SECRET = config['ELIXIR_SECRET']

if config["DEVELOPMENT"] == True:
    _AUTHORIZE_URL = "http://localhost:9090/auth"
    _ACCESS_TOKEN_URL = "http://localhost:9090/token"
    _JWKS_URL = "http://localhost:9090/certs"
    _USERINFO_ENDPOINT = "http://localhost:9090/me"
    _ISSUER_URL = "http://localhost:9090"
else:
    _AUTHORIZE_URL = "https://login.elixir-czech.org/oidc/authorize"
    _ACCESS_TOKEN_URL = "https://login.elixir-czech.org/oidc/token"
    _JWKS_URL = "https://login.elixir-czech.org/oidc/jwk"
    _USERINFO_ENDPOINT = "https://login.elixir-czech.org/oidc/userinfo"
    _ISSUER_URL = "https://login.elixir-czech.org/oidc/"
    _REVOCATION_URL = "https://login.elixir-czech.org/oidc/revoke"

_CLIENT_METADATA = ClientMetadata(client_id=_CLIENT_ID, client_secret=_CLIENT_SECRET)

_PROVIDER_METADATA = ProviderMetadata(issuer=_ISSUER_URL,
                                     authorization_endpoint=_AUTHORIZE_URL,
                                     userinfo_endpoint=_USERINFO_ENDPOINT,
                                     token_endpoint=_ACCESS_TOKEN_URL,
                                     jwks_uri=_JWKS_URL)

PROVIDER_CONFIG = ProviderConfiguration(provider_metadata=_PROVIDER_METADATA,
                                        client_metadata=_CLIENT_METADATA)
                                        #auth_request_params={"redirect_uri": config["ELIXIR_REDIRECT_URI"]})


def revoke_token(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if config["DEVELOPMENT"] == False:
            logging.debug('Revoking token...')
            user_session = handle_uninitialised_session()
            if user_session is not None:
                token_payload = {"token": user_session.access_token}
                response = requests.get(_REVOCATION_URL,
                                        params=token_payload,
                                        auth=HTTPBasicAuth(config["ELIXIR_ID"],
                                                           config["ELIXIR_SECRET"]))
                if response.status_code == 200:
                    logging.debug("Your token has been successfully revoked")
                    return fn(*args, **kwargs)
                else:
                    logging.debug(f'{response.status_code}: something went wrong with token revocation')
                    return fn(*args, **kwargs)
            else:
                return fn(*args, **kwargs)
        return fn(*args, **kwargs)
    return wrapped


def handle_uninitialised_session():
    try:
        session = UserSession(flask.session)
        return session
    except UninitialisedSession as e:
        logging.debug('The user was already logged out')
        return None
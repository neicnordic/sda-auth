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
_AUTHORISATION_URL = config['ELIXIR_AUTH_URL']
_ACCESS_TOKEN_URL = config['ELIXIR_TOKEN_URL']
_JWKS_URL = config['ELIXIR_CERTS_URL']
_USERINFO_URL = config['ELIXIR_USERINFO_URL']
_ISSUER_URL = config['ELIXIR_ISSUER_URL']
_TOKEN_REVOCATION_URL = config['ELIXIR_REVOCATION_URL']

_CLIENT_METADATA = ClientMetadata(client_id=_CLIENT_ID, client_secret=_CLIENT_SECRET)

_PROVIDER_METADATA = ProviderMetadata(issuer=_ISSUER_URL,
                                     authorization_endpoint=_AUTHORISATION_URL,
                                     userinfo_endpoint=_USERINFO_URL,
                                     token_endpoint=_ACCESS_TOKEN_URL,
                                     jwks_uri=_JWKS_URL)

PROVIDER_CONFIG = ProviderConfiguration(provider_metadata=_PROVIDER_METADATA,
                                        client_metadata=_CLIENT_METADATA)
                                        #auth_request_params={"redirect_uri": config["ELIXIR_REDIRECT_URI"]})


def revoke_token(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if config["DEVELOPMENT"]:
            return fn(*args, **kwargs)
        else:
            logging.debug('Revoking token...')
            user_session = handle_uninitialised_session()
            if user_session is None:
                return fn(*args, **kwargs)
            else:
                token_payload = {"token": user_session.access_token}
                response = requests.get(_TOKEN_REVOCATION_URL,
                                        params=token_payload,
                                        auth=HTTPBasicAuth(config["ELIXIR_ID"],
                                                           config["ELIXIR_SECRET"]))
                if response.status_code == 200:
                    logging.info("Your token has been successfully revoked")
                    return fn(*args, **kwargs)
                else:
                    logging.warning(f'{response.status_code}: {response.content}')
                    return fn(*args, **kwargs)
    return wrapped


def handle_uninitialised_session():
    try:
        session = UserSession(flask.session)
        return session
    except UninitialisedSession as e:
        logging.debug('The user was already logged out')
        return None
from flask_pyoidc.provider_configuration import ProviderConfiguration, ProviderMetadata, ClientMetadata
from settings import SERVICE_SETTINGS as config

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
    _JWKS_URL = ""
    _USERINFO_ENDPOINT = "https://login.elixir-czech.org/oidc/userinfo"
    _ISSUER_URL =  "https://login.elixir-czech.org/oidc"


_CLIENT_METADATA = ClientMetadata(client_id=_CLIENT_ID, client_secret=_CLIENT_SECRET)

_PROVIDER_METADATA = ProviderMetadata(issuer=_ISSUER_URL,
                                     authorization_endpoint=_AUTHORIZE_URL,
                                     userinfo_endpoint=_USERINFO_ENDPOINT,
                                     token_endpoint=_ACCESS_TOKEN_URL,
                                     jwks_uri=_JWKS_URL)

PROVIDER_CONFIG = ProviderConfiguration(provider_metadata=_PROVIDER_METADATA,
                                        client_metadata=_CLIENT_METADATA)
import yaml
import os
from pathlib import Path
import logging


LOG = logging.getLogger("default")
LOG.propagate = False

SETTINGS_FILE = os.environ.get("CONF_FILE_PATH", "settings-sample.yaml")

try:
    yaml_settings_fh = open(Path(SETTINGS_FILE))
except FileNotFoundError as e:
    LOG.error(e)

yaml_settings = yaml.safe_load(yaml_settings_fh)
yaml_settings_fh.close()

SERVICE_SETTINGS = {"LOG_LEVEL": os.environ.get("LOG_LEVEL", yaml_settings.get("logLevel", "DEBUG")),
                    "ELIXIR_REDIRECT_URI": os.environ.get("ELIXIR_REDIRECT_URI", yaml_settings.get("elixir", {}).get("redirectUri", "http://localhost:31111/elixir/login")),
                    "ELIXIR_ID": os.environ.get("ELIXIR_ID", yaml_settings.get("elixir", {}).get("id", "XC56EL11xx")),
                    "ELIXIR_SECRET": os.environ.get("ELIXIR_SECRET", yaml_settings.get("elixir", {}).get("secret", "wHPVQaYXmdDHg")),
                    "ELIXIR_AUTH_URL": os.environ.get("ELIXIR_AUTH_URL", yaml_settings.get("elixir", {}).get("authUrl", "http://localhost:9090/auth")),
                    "ELIXIR_TOKEN_URL": os.environ.get("ELIXIR_TOKEN_URL", yaml_settings.get("elixir", {}).get("tokenUrl", "http://localhost:9090/token")),
                    "ELIXIR_CERTS_URL": os.environ.get("ELIXIR_CERTS_URL", yaml_settings.get("elixir", {}).get("certsUrl", "http://localhost:9090/certs")),
                    "ELIXIR_USERINFO_URL": os.environ.get("ELIXIR_USERINFO_URL", yaml_settings.get("elixir", {}).get("userInfo", "http://localhost:9090/me")),
                    "ELIXIR_ISSUER_URL": os.environ.get("ELIXIR_ISSUER_URL", yaml_settings.get("elixir", {}).get("issuer", "http://localhost:9090")),
                    "ELIXIR_REVOCATION_URL": os.environ.get("ELIXIR_REVOCATION_URL", yaml_settings.get("elixir", {}).get("revocationUrl", "http://localhost:9090")),
                    "CEGA_AUTH_URL": os.environ.get("CEGA_AUTH_URL", yaml_settings.get("cega", {}).get("authUrl", "http://localhost:8443/lega/v1/legas/users/")),
                    "ELIXIR_SCOPE": os.environ.get("ELIXIR_SCOPE", yaml_settings.get("elixir", {}).get("scope", "openid")),
                    "CEGA_ID": os.environ.get("CEGA_ID", yaml_settings.get("cega", {}).get("id", "dummy")),
                    "CEGA_SECRET": os.environ.get("CEGA_SECRET", yaml_settings.get("cega", {}).get("secret", "dummy")),
                    "JWT_PRIVATE_KEY": os.environ.get("JWT_PRIVATE_KEY", yaml_settings.get("cega", {}).get("jwtPrivateKey", "keys/sign-jwt.key")),
                    "JWT_SIGNATURE_ALG": os.environ.get("JWT_SIGNATURE_ALG", yaml_settings.get("cega", {}).get("jwtSignatureAlg", "ES256")),
                    "BIND_ADDRESS": os.environ.get("BIND_ADDRESS", yaml_settings.get("bindAddress", "localhost")),
                    "PORT": int(os.environ.get("PORT", yaml_settings.get("port", 31111))),
                    "SERVER_NAME": os.environ.get("SERVER_NAME", yaml_settings.get("serverName", "localhost:31111")),
                    "URL_SCHEME": os.environ.get("URL_SCHEME", yaml_settings.get("urlScheme", "http")),
                    "SECRET_KEY": os.environ.get("SECRET_KEY", yaml_settings.get("secretKey", "de8b3fe55c7d9fb32de24b8428470876f00021f88c9eb7ff")),
                    "ENABLE_TLS": eval(os.environ.get("ENABLE_TLS", yaml_settings.get("tls", {}).get("enableTLS", "False"))),
                    "CERT_FILE": os.environ.get("CERT_FILE", yaml_settings.get("tls", {}).get("certFile", None)),
                    "KEY_FILE": os.environ.get("KEY_FILE", yaml_settings.get("tls", {}).get("keyFile", None)),
                    "CA_CERTS": os.environ.get("CA_CERTS", yaml_settings.get("tls", {}).get("caCerts", None))}

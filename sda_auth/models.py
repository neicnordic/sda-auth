import flask_login
from datetime import datetime
from datetime import timedelta
from jose import jwt
import logging
from pathlib import Path
from sda_auth.settings import SERVICE_SETTINGS as config
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

_PROTOCOL = "https://" if config["ENABLE_TLS"] else "http://"
_JWT_PRIVATE_KEY = config['JWT_PRIVATE_KEY']
_JWT_SIGNATURE_ALG = config['JWT_SIGNATURE_ALG']
_JWT_ISSUER = _PROTOCOL + config['SERVER_NAME']

LOG = logging.getLogger("ega")
LOG.propagate = False


class EgaUser(flask_login.UserMixin):
    """An EGA user."""

    def __init__(self, ega_id):
        """Construct a user class. It takes id and password as arguments."""
        self.ega_id = ega_id
        self.jwt_token = self.generate_jwt_token()
        super()

    def get_id(self):
        """Return the id of a user instance."""
        return self.ega_id

    def get_jwt_token(self):
        """Return user's jwt token."""
        return self.jwt_token

    @staticmethod
    def _load_jwt_private_key():
        """Load jwt private key."""
        try:
            with open(Path(_JWT_PRIVATE_KEY), 'rb') as pem_data:
                private_key_data = pem_data.read()
                return serialization.load_pem_private_key(private_key_data,
                                                          backend=default_backend(),
                                                          password=None)
        except Exception as e:
            LOG.error('%s could not be loaded', _JWT_PRIVATE_KEY)
            logging.exception(e)
            exit(1)

    def generate_jwt_token(self):
        """Generate a jwt token for a user."""
        expiration_time = datetime.now() + timedelta(days=7)
        jwt_entries = {"iss": _JWT_ISSUER,
                       "sub": self.ega_id,
                       "exp": expiration_time}

        return jwt.encode({**jwt_entries},
                          self._load_jwt_private_key(),
                          algorithm=_JWT_SIGNATURE_ALG)

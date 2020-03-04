import flask_login
from settings import SERVICE_SETTINGS as config
import jwt


_JWT_PRIVATE_KEY = config['JWT_PRIVATE_KEY']
_JWT_ISSUER = config['SERVER_NAME']



class EgaUser(flask_login.UserMixin):
    """Class that that represents a EGA user."""

    def __init__(self, ega_id, ega_password=None):
        """Construct a user class. It takes id and password as arguments."""
        self.ega_id = ega_id
        self.ega_password = ega_password
        self.jwt_token = self.generate_jwt_token()
        super()

    def get_id(self):
        """Return the id of a user instance."""
        return self.ega_id

    def get_password(self):
        """Return the password of a user instance."""
        return self.ega_password
    def get_jwt_token(self):
        return self.jwt_token
    def generate_jwt_token(self):
        jwt_entries={"iss": _JWT_ISSUER,
                     "sub": self.ega_id}
        return jwt.encode({**jwt_entries}, _JWT_PRIVATE_KEY).decode("utf-8")
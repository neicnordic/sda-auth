from sda_auth.settings import SERVICE_SETTINGS as config
import requests
from requests.auth import HTTPBasicAuth
import logging
import flask_login
from models import EgaUser
import json
from flask import redirect, url_for
import bcrypt


_AUTHORISATION_URL = config['CEGA_AUTH_URL']
_CEGA_ID = config['CEGA_ID']
_CEGA_SECRET = config['CEGA_SECRET']

LOG = logging.getLogger("ega")
LOG.propagate = False


class EgaAuthenticator:
    """EGA authentication handler."""

    def __init__(self, id_type='username'):
        """Construct a EGA authenticator class."""
        self.id_type = id_type

    def authenticate_with_ega(self, username, password):
        """Sign in with EGA credentials."""
        ega_user = EgaUser(ega_id=username)

        id_type_payload = {"idType": self.id_type}
        user_id = ega_user.get_id()
        response = requests.get(f'{_AUTHORISATION_URL}{user_id}',
                                params=id_type_payload,
                                auth=HTTPBasicAuth(_CEGA_ID,
                                                   _CEGA_SECRET))

        if response.status_code == 200:
            password_hash = json.loads(response.text)['response']['result'][0]['passwordHash']
            password_is_correct = self.verify_password(response_password=password_hash,
                                                       user_password=password)

            if password_is_correct:
                flask_login.login_user(ega_user)
                LOG.info('%s has been successfully logged in', username)
                return True
            else:
                LOG.info('%s could not be authenticated due to invalid credentials', username)
                return None

        else:
            LOG.info('%s could not be authenticated due to this response: %s: %s', username, response.status_code, response.content)
            return None

    @staticmethod
    def logout_from_ega():
        """Sign out from EGA."""
        flask_login.logout_user()
        LOG.debug("You have been successfully logged out")
        return redirect(url_for("index"), 302)

    @staticmethod
    def is_logged_in():
        """Check if user is logged in."""
        if flask_login.current_user.is_authenticated:
            return flask_login.current_user
        else:
            return None

    @staticmethod
    def verify_password(response_password, user_password):
        """Verify that password hashes match."""
        return bcrypt.checkpw(user_password.encode("utf-8"), response_password.encode("utf-8"))

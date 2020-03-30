from settings import SERVICE_SETTINGS as config
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


def authenticate_with_ega(username, password):
    """Sign in with EGA credentials."""
    ega_user = EgaUser(ega_id=username)

    id_type_payload = {"idType": "username"}
    response = requests.get(f'{_AUTHORISATION_URL}{ega_user.get_id()}',
                            params=id_type_payload,
                            auth=HTTPBasicAuth(_CEGA_ID,
                                               _CEGA_SECRET))

    if response.status_code == 200:
        password_hash = json.loads(response.text)['response']['result'][0]['passwordHash']
        password_is_correct = verify_password(response_password=password_hash,
                                              user_password=password)

        if password_is_correct:
            flask_login.login_user(ega_user)
            logging.info("You have been successfully logged in with EGA")
            return True
        else:
            logging.warning("Password hashes did not match")
            return None

    else:
        logging.warning(f'{response.status_code}: {response.content}')
        return None


def logout_from_ega():
    """Sign out from EGA."""
    flask_login.logout_user()
    logging.info("You have been successfully logged out from EGA")
    return redirect(url_for("index"), 302)


def is_logged_in():
    """Check if user is logged in."""
    if flask_login.current_user.is_authenticated:
        return flask_login.current_user
    else:
        return None


def verify_password(response_password, user_password):
    """Verify that password hashes match."""
    return bcrypt.checkpw(user_password.encode("utf-8"), response_password.encode("utf-8"))

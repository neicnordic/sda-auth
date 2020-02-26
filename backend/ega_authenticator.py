from settings import SERVICE_SETTINGS as config
import requests
from requests.auth import HTTPBasicAuth
import logging
import flask_login
from models import EgaUser
import json
from flask import render_template, jsonify, redirect, url_for


_AUTHORISATION_URL = config['CEGA_AUTH_URL']


def authenticate_with_ega(username, password):
    ega_user = EgaUser(ega_id=username, ega_secret=password)
    id_type_payload = {"idType": "username"}
    response = requests.get(f'{_AUTHORISATION_URL}{ega_user.get_id()}',
                                params=id_type_payload,
                                auth=HTTPBasicAuth(ega_user.get_id(),
                                                   ega_user.get_secret()))
    if response.status_code == 200:
        flask_login.login_user(ega_user)
        logging.info("You have been successfully logged in with EGA")
        return response.json()
    else:
        logging.warning(f'{response.status_code}: {response.content}')
        return None


def logout_from_ega():
    flask_login.logout_user()
    logging.info("You have been successfully logged out from EGA")
    return redirect(url_for("index"), 302)


def is_logged_in():
    if flask_login.current_user.is_authenticated:
        return flask_login.current_user
    else:
        return None
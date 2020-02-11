import os
import requests
import json
import logging
import datetime
import auth
from gevent.pywsgi import WSGIServer
import flask
from flask import (
    Blueprint, Flask, request, jsonify, redirect, url_for
)
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration
from flask_pyoidc.user_session import UserSession
from settings import SERVICE_SETTINGS as config

logging.basicConfig(level=config["LOG_LEVEL"])

app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")

app.config.update({'SERVER_NAME': config['SERVER_NAME'],
                   #"OIDC_REDIRECT_ENDPOINT": config["ELIXIR_REDIRECT_URI"],
                   'SECRET_KEY': config['SECRET_KEY'],
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=1).total_seconds(),
                   'PREFERRED_URL_SCHEME': 'http',
                   'DEBUG': True})

# Setup OIDC Authenticator
auth = OIDCAuthentication({'default': auth.PROVIDER_CONFIG}, app)

# Start the Elixir Blueprint
elixir_blueprint = Blueprint("auth", __name__, url_prefix="/elixir")


@app.route("/")
def auth_home():
    return app.send_static_file("index.html")


@app.route("/redirect_uri")
def redirection():
    return "You have been redirected here"


@auth.error_view
def error_view_oidc(error=None, error_description=None):
 return jsonify({'error': error, 'message': error_description})


@elixir_blueprint.route("/login")
@auth.oidc_auth('default')
def login_to_elixir():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@elixir_blueprint.route("/logout")
@auth.oidc_logout
def logout_from_elixir():
    return "You have been successfully logged out from Elixir AAI"


def start_app(flask_app):
    flask_app.register_blueprint(elixir_blueprint)


def main():
    start_app(app)
    logging.debug(">>>>> Starting Elixir server at http://{}:{} <<<<<".format(config["BIND_ADDRESS"], config["PORT"]))
    # Create gevent WSGI server
    wsgi_server = WSGIServer((config["BIND_ADDRESS"], config["PORT"]),
                             app.wsgi_app)
                            # certfile=config["CERT_FILE"],
                            # keyfile=config["KEY_FILE"],
                            # ca_certs=config["CA_CERTS"])
    # Start gevent WSGI server
    wsgi_server.serve_forever()


if __name__ == "__main__":
    main()
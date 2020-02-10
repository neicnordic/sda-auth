import os
import requests
import json
import logging
import auth
from gevent.pywsgi import WSGIServer
from flask import (
    Blueprint, Flask, request, jsonify, redirect, url_for
)
from settings import SERVICE_SETTINGS as config

logging.basicConfig(level=config["LOG_LEVEL"])

app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")

elixir_blueprint = Blueprint("auth", __name__, url_prefix="/elixir")

@app.route("/", methods=['GET'])
def auth_home():
    return app.send_static_file("index.html")


@elixir_blueprint.route("/login", methods=['GET'])
def login_to_elixir():
    return redirect(auth._OAUTH_AUTHORIZE_URL, code=302)


@elixir_blueprint.route("/logout", methods=['GET'])
def logout_from_elixir():
    return "Logging out..."


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
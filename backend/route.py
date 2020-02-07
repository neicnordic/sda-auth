import os
import requests
import json
import logging
from gevent.pywsgi import WSGIServer
from flask import (
    Blueprint, Flask, render_template, request, abort, redirect, url_for
)
from settings import SERVICE_SETTINGS as config

logging.basicConfig(level=config["LOG_LEVEL"])


app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")
auth_blueprint = Blueprint("auth", __name__, url_prefix="/auth")


@app.route("/")
def ega_home():
    return redirect(url_for("auth.authenticate_to_elixir"))


@auth_blueprint.route("/")
def authenticate_to_elixir():
    return app.send_static_file("index.html")


def start_app(flask_app):
    flask_app.register_blueprint(auth_blueprint)


def main():
    start_app(app)
    logging.debug(">>>>> Starting Elixir server at http://{}:{} <<<<<".format(config["BIND_ADDRESS"], config["PORT"]))
    # Create gevent WSGI server
    wsgi_server = WSGIServer((config["BIND_ADDRESS"], config["PORT"]),
                             app.wsgi_app)
                            # certfile=settings.CERT_FILE,
                            # keyfile=settings.KEY_FILE,
                            # ca_certs=settings.CA_CERTS)
    # Start gevent WSGI server
    wsgi_server.serve_forever()


if __name__ == "__main__":
    main()
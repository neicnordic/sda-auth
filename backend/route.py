from gevent import monkey
monkey.patch_all()

import os
import requests
import json
import logging
import datetime
from gevent.pywsgi import WSGIServer
from flask import (
    Flask, render_template
)
import elixir_blueprint, ega_blueprint
import elixir_authenticator
from flask_pyoidc import OIDCAuthentication
from flask_login import UserMixin, login_manager, LoginManager
from settings import SERVICE_SETTINGS as config
from models import EgaUser


logging.basicConfig(level=config["LOG_LEVEL"])

app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")

app.config.update({'SERVER_NAME': config['SERVER_NAME'],
                   "OIDC_REDIRECT_ENDPOINT": config["ELIXIR_REDIRECT_URI"],
                   'SECRET_KEY': config['SECRET_KEY'],
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(seconds=60),
                   'PREFERRED_URL_SCHEME': config['URL_SCHEME'],
                   "SESSION_PERMANENT": True,
                   'DEBUG': True})

# Setup OIDC Authenticator
authenticator = OIDCAuthentication({'default': elixir_authenticator.PROVIDER_CONFIG}, app)

# Setup EGA Authenticator
ega_login_manager = LoginManager()
ega_login_manager.init_app(app)

@ega_login_manager.user_loader
def load_user(loaded_ega_id):
    return EgaUser(ega_id=loaded_ega_id)


@app.route("/")
def index():
    return render_template("index.html")


def start_app(flask_app):
    flask_app.register_blueprint(elixir_blueprint.elixir_bp)
    flask_app.register_blueprint(ega_blueprint.ega_bp)


def main():
    start_app(app)
    logging.debug(">>>>> Starting authentication server at {}:{} <<<<<".format(config["BIND_ADDRESS"], config["PORT"]))
    # Create gevent WSGI server
    wsgi_server = WSGIServer((config["BIND_ADDRESS"], config["PORT"]),
                              app.wsgi_app)
                            # certfile=config["CERT_FILE"],
                            # keyfile=config["KEY_FILE"],
                            # ca_certs=config["CA_CERTS"])
    # Start gevent WSGI server
    wsgi_server.serve_forever()
    #app.run(host=config["BIND_ADDRESS"], port=config["PORT"])

if __name__ == "__main__":
    main()
from gevent import monkey
monkey.patch_all() # noqa

import logging
from pathlib import Path
import datetime
import sda_auth.elixir_blueprint as elixir_blueprint
import sda_auth.ega_blueprint as ega_blueprint
from gevent.pywsgi import WSGIServer
from flask import (
    Flask, render_template
)
from flask_login import LoginManager
from sda_auth.settings import SERVICE_SETTINGS as config
from sda_auth.models import EgaUser
from sda_auth.utils.loggers import setup_custom_loggers


app = Flask(__name__, template_folder="../frontend/templates", static_folder="../frontend/static")

app.config.update({'SERVER_NAME': config['SERVER_NAME'],
                   "OIDC_REDIRECT_ENDPOINT": config["ELIXIR_REDIRECT_URI"],
                   'SECRET_KEY': config['SECRET_KEY'],
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(seconds=60),
                   'PREFERRED_URL_SCHEME': config['URL_SCHEME'],
                   "SESSION_PERMANENT": True})

setup_custom_loggers(config["LOG_LEVEL"])
LOG = logging.getLogger("default")
LOG.propagate = False


# Setup EGA Authenticator
ega_login_manager = LoginManager()
ega_login_manager.init_app(app)


@ega_login_manager.user_loader
def load_user(loaded_ega_id):
    """Load logged in user."""
    return EgaUser(ega_id=loaded_ega_id)


@app.route("/")
def index():
    """Return the index page."""
    return render_template("index.html")


def start_app(flask_app):
    """Register EGA and Elixir blueprints."""
    flask_app.register_blueprint(elixir_blueprint.elixir_bp)
    flask_app.register_blueprint(ega_blueprint.ega_bp)


def files_exist(files):
    """Check if the given files exist."""
    for f in files:
        if Path(f).is_file():
            continue
        else:
            LOG.error('%s does not exist', f)
            return False
    return True


def main():
    """Start the wsgi serving the application."""
    start_app(app)
    LOG.debug(">>>>> Starting authentication server at %s:%s <<<<<", config["BIND_ADDRESS"], config["PORT"])
    LOG.debug('TLS flag is %s', config["ENABLE_TLS"])

    # Create gevent WSGI server
    wsgi_tls_params = dict()

    if config["ENABLE_TLS"]:
        wsgi_tls_params = {"certfile": config["CERT_FILE"],
                           "keyfile": config["KEY_FILE"]}

        if config["CA_CERTS"] is not None:
            wsgi_tls_params["ca_certs"] = config["CA_CERTS"]

        if not files_exist(wsgi_tls_params.values()):
            LOG.debug("Bad configuration. Exiting...")
            exit(1)

    wsgi_server = WSGIServer((config["BIND_ADDRESS"], config["PORT"]),
                             app.wsgi_app,
                             **wsgi_tls_params)

    # Start gevent WSGI server
    wsgi_server.serve_forever()


if __name__ == "__main__":
    main()

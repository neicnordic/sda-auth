from sda_auth.elixir_authenticator import ElixirAuthenticator
import flask
import logging
from flask import Blueprint, render_template, redirect, url_for, jsonify

elixir_bp = Blueprint("elixir", __name__, url_prefix="/elixir")
elixir_authenticator = ElixirAuthenticator()

LOG = logging.getLogger("elixir")
LOG.propagate = False


def login():
    """Sign in with Elixir."""
    req = flask.request.args
    state = flask.session.get("state", None)
    LOG.debug("Request coming")
    LOG.debug(req)
    if 'error' in req:
        LOG.info("User could not be authenticated due to: %s", req["error"])
        return jsonify({"status": "Error"}), 401
    elif 'code' in req and state is not None:
        elixir_authenticator.handle_authentication_response()
        tok_req = elixir_authenticator.send_token_request()

        try:
            token_resp = elixir_authenticator.handle_token_response(tok_req)
        except Exception as e:
            LOG.error(e)
            return redirect(url_for("index"))

        userinfo_req = elixir_authenticator.send_userinfo_request(token_resp)
        userinfo = elixir_authenticator.handle_userinfo_response(userinfo_req)
        LOG.debug(userinfo)
        elixir_id = userinfo['sub']
        access_token = token_resp['access_token']
        LOG.info('%s has been successfully logged in and granted the token %s', elixir_id, access_token)
        return render_template("elixir_login_success.html",
                               user_name=elixir_id,
                               access_token=access_token,
                               passport=userinfo.get('ga4gh_passport_v1', None))
    else:
        LOG.debug("Authenticating request...")
        return elixir_authenticator.authenticate()


def logout():
    """Sign out from Elixir."""
    elixir_authenticator.revoke_token()
    elixir_authenticator.logout_from_elixir()
    return redirect(url_for("index"), 302)


elixir_bp.add_url_rule('/logout', 'logout', view_func=logout)
elixir_bp.add_url_rule('/login', 'login', view_func=login, methods=['GET', 'POST'])

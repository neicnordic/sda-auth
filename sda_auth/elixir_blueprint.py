import elixir_authenticator
import flask
import logging
from flask import Blueprint, render_template, redirect, url_for, jsonify


elixir_bp = Blueprint("elixir", __name__, url_prefix="/elixir")


def login():
    """Sign in with Elixir."""
    req = flask.request.args
    state = flask.session.get("state", None)
    logging.debug("Request coming")
    logging.debug(req)
    if 'error' in req:
        logging.debug("Response contains error")
        return jsonify({"status": "Error"}), 401
    elif 'code' in req and state is not None:
        logging.debug("Code resp")
        elixir_authenticator.handle_authentication_response()
        tok_req = elixir_authenticator.send_token_request()
        logging.debug("Access token resp")
        token_resp = elixir_authenticator.handle_token_response(tok_req)
        userinfo_req = elixir_authenticator.send_userinfo_request(token_resp)
        logging.debug("User info token resp")
        userinfo = elixir_authenticator.handle_userinfo_response(userinfo_req)
        logging.debug(userinfo)
        return render_template("elixir_login_success.html",
                               user_name=userinfo['sub'],
                               access_token=token_resp['access_token'],
                               passport=userinfo.get('ga4gh_passport_v1', None))
    else:
        logging.debug("Authenticating request...")
        return elixir_authenticator.authenticate()


def logout():
    """Sign out from Elixir."""
    elixir_authenticator.revoke_token()
    elixir_authenticator.logout_from_elixir()
    return redirect(url_for("index"), 302)


elixir_bp.add_url_rule('/logout', 'logout', view_func=logout)
elixir_bp.add_url_rule('/login', 'login', view_func=login, methods=['GET', 'POST'])

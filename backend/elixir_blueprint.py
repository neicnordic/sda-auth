import elixir_authenticator
import flask
from flask import Blueprint, render_template, jsonify, redirect, url_for
from flask_pyoidc.user_session import UserSession
from flask_pyoidc import OIDCAuthentication
from elixir_authenticator import revoke_token
from route import authenticator

elixir_bp = Blueprint("elixir", __name__, url_prefix="/elixir")

@elixir_bp.route("/auth")
@authenticator.oidc_auth('default')
def login():
    return redirect(url_for("elixir.info"), 302)


@elixir_bp.route("/auth/info")
def info():
    user_session = elixir_authenticator.handle_uninitialised_session()
    if user_session and user_session.is_authenticated():
        print(user_session.userinfo)
        return render_template("elixir_login_success.html",
                    user_name=user_session.userinfo['sub'],
                    access_token=user_session.access_token)
    else:
        return redirect(url_for("index"), 302)
        

@elixir_bp.route("/logout")
@revoke_token
@authenticator.oidc_logout
def logout():
    return redirect(url_for("index"), 302)


@elixir_bp.route("/login")
def callback_uri():
    resp = jsonify(success=True)
    return resp
import elixir_authenticator
from flask import Blueprint, render_template, redirect, url_for


elixir_bp = Blueprint("elixir", __name__, url_prefix="/elixir")


def login():
    """Sign in with Elixir."""
    response = elixir_authenticator.authenticate_with_elixir()
    if response is None:
        return redirect(url_for("elixir.info"), 302)
    else:
        return elixir_authenticator.authenticate_with_elixir()


def info():
    """Display Elixir user info."""
    user_session = elixir_authenticator.handle_uninitialised_session()
    if user_session and user_session.is_authenticated():
        print(user_session.userinfo)
        return render_template("elixir_login_success.html",
                               user_name=user_session.userinfo['sub'],
                               access_token=user_session.access_token)
    else:
        return redirect(url_for("index"), 302)


def logout():
    """Sign out from Elixir."""
    elixir_authenticator.logout_from_elixir()
    elixir_authenticator.revoke_token()
    return redirect(url_for("index"), 302)


def callback_uri():
    """Register callback endpoint for login."""
    return elixir_authenticator.handle_auth_response()


elixir_bp.add_url_rule('/auth', 'login', view_func=login)
elixir_bp.add_url_rule('/info', 'info', view_func=info)
elixir_bp.add_url_rule('/logout', 'logout', view_func=logout)
elixir_bp.add_url_rule('/login', 'callback_uri', view_func=callback_uri, methods=['GET', 'POST'])

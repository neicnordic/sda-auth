import flask
from flask import Blueprint, render_template, jsonify, url_for, redirect, flash
from flask_pyoidc.user_session import UserSession
import ega_authenticator
import forms
from models import EgaUser
import logging

ega_bp = Blueprint("ega", __name__, url_prefix="/ega")

@ega_bp.route("/login", methods=['GET', 'POST'])
def login():
    if ega_authenticator.is_logged_in():
        return redirect(url_for("ega.info"), 302)
    else:
        form = forms.EgaLoginForm()
        if form.validate_on_submit():
            logging.info("Login form was successfullly validated")
            if ega_authenticator.authenticate_with_ega(username=form.username.data, password=form.password.data):
                return redirect(url_for("ega.info"), 302)
            else:
                flash('Wrong username or password.')
        else:
            logging.info("Login form was not validated")
    return render_template('ega_login_form.html', title='EGA login', form=form)


@ega_bp.route("/logout")
def logout():
    return ega_authenticator.logout_from_ega()


@ega_bp.route("/login/info")
def info():
    logged_in_user = ega_authenticator.is_logged_in()
    if logged_in_user:
        return render_template('ega_login_success.html',
                               user_name=logged_in_user.get_id(),
                               access_token=logged_in_user.get_jwt_token())
    else:
        return redirect(url_for("index"), 302)

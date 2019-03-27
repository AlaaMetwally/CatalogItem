from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_login import login_user, logout_user, login_required
from models import User, app, db

# configuring app
auth = Blueprint('auth', __name__)


# route to go to the login/register web page
@auth.route('/login_register')
def login_register():
    return render_template(
                            'login_register_forms.html',
                            status_login_register="active")


# route to register
@auth.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    password = request.form.get('psw')
    confirm_password = request.form.get('psw-repeat')
    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists', 'danger')
        return render_template(
                            'login_register_forms.html',
                            status_login_register="active", register="True")

    if password != confirm_password:
        flash('password not equal to confirm password', 'danger')
        return render_template(
                            'login_register_forms.html',
                            status_login_register="active", register="True")

    new_user = User(
                    email=email,
                    password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('index'))


# route to login the project
@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('psw')
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Please check your login details and try again.', 'danger')
        return render_template(
                                'login_register_forms.html',
                                status_login_register="active", login="True")
    elif not check_password_hash(user.password, password):
        flash('Please check your login details and try again.', 'danger')
        return render_template(
                                'login_register_forms.html',
                                status_login_register="active", login="True")
    login_user(user)
    return redirect(url_for('index'))


# route to logout the project
@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

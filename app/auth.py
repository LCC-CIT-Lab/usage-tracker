from cryptography.fernet import Fernet
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import LoginManager, login_user, logout_user
from app.models import db, User 
from app.forms import LoginForm, LogoutForm
from app.admin import create_admin
from .config import load_config

import subprocess
import os

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():

    # Check if any admin exists
    admin_exists = User.query.filter_by(is_admin=True).first() is not None

    # If no admin exists, create an admin
    if not admin_exists:
        create_admin(current_app._get_current_object())

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if not username or not password:
            flash('Please enter both username and password.')
            return redirect(url_for('auth.login'))

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.')
            next_page = request.args.get('next')
            # Redirect to the admin dashboard if the user is an admin
            if user.is_admin:
                return redirect(next_page or url_for('admin.admin_dashboard'))
            # Redirect to query selection if the user is not an admin
            # and either there is no next page or the next page is not admin_dashboard
            else:
                if not next_page or url_for('admin.admin_dashboard') not in next_page:
                    return redirect(url_for('admin.admin_dashboard'))
                else:
                    flash('Access denied: You do not have the necessary permissions.')
                    return redirect(url_for('admin.admin_dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)


@auth_bp.route('/logout', methods=['POST'])
def logout():
    form = LogoutForm()
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('auth.login'))

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message.decode()


def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message.encode()).decode()
    return decrypted_message


def generate_token(username, expiration=1800):
    secret_key = current_app.config['SECRET_KEY']
    s = Serializer(secret_key)
    return s.dumps({'username': username})


def validate_token(token, expiration=1800):
    secret_key = current_app.config['SECRET_KEY']
    s = Serializer(secret_key)
    try:
        data = s.loads(token, max_age=expiration)
    except SignatureExpired:
        return None  # valid token, but expired
    except BadSignature:
        return None  # invalid token
    return data.get('username')

def confirm_token(token, expiration=1800):
    secret_key_bytes = app.secret_key
    s = Serializer(secret_key_bytes)
    try:
        data = s.loads(token, max_age=expiration)
    except:
        return False
    return data['username']
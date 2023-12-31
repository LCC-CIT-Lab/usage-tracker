from flask import Flask, render_template
from flask_login import LoginManager
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix
from app.auth import auth_bp
from app.admin import admin_bp, create_admin
from app.main import main_bp
from app.models import db
from .config import load_config

import os
import logging

from logging.handlers import RotatingFileHandler
from flask_wtf.csrf import CSRFProtect

# Global variable to track the first request
has_run = False

# Initialize extensions
login_manager = LoginManager()
migrate = Migrate()

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1)

    # Load configuration
    inscopeconfig = load_config()
    app.config.update(inscopeconfig)

    app.run()

    csrf = CSRFProtect(app)

    # Set configuration from the loaded config
    app.config['SECRET_KEY'] = app.config['encryption']['SECRET_KEY']
    app.config['SESSION_COOKIE_SECURE'] = app.config['encryption']['SESSION_COOKIE_SECURE']
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['flask']['SQLALCHEMY_DATABASE_URI']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['DEBUG'] = app.config['flask']['DEBUG']

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(main_bp)

    # Setup login manager
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User  # Local import to avoid circular dependency
        return User.query.get(int(user_id))

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500

    # Context processor to add logout form to all templates
    @app.context_processor
    def inject_logout_form():
        from app.forms import LogoutForm  # Local import to avoid circular dependency
        return dict(logout_form=LogoutForm())

    return app

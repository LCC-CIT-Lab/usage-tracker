from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix
from app.auth import auth_bp
from app.admin import admin_bp, create_admin, start_scheduler, setup_logging
from app.main import main_bp
from app.models import db, DatabaseLogHandler
from .config import load_config

import os
import toml
import logging

from logging.handlers import RotatingFileHandler
from flask_wtf.csrf import CSRFProtect

# Global variable to track the first request
has_run = False

# Initialize extensions
login_manager = LoginManager()
migrate = Migrate()
start_scheduler()

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1)

    app.run(ssl_context='adhoc')   # The ssl_context='adhoc' is for demo purposes. Use proper SSL in production.

    # Load configuration
    config = load_config()
    print(config)  # Add this line to debug the config loading
    app.config.update(config)

    csrf = CSRFProtect(app)

    # Set configuration from the loaded config
    app.config['SECRET_KEY'] = app.config['encryption']['SECRET_KEY']
    app.config['SESSION_COOKIE_SECURE'] = app.config['encryption']['SESSION_COOKIE_SECURE']
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['flask']['SQLALCHEMY_DATABASE_URI']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['DEBUG'] = config['flask']['DEBUG']

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    setup_logging(app)


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

    # Logging setup
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('App startup')

    return app
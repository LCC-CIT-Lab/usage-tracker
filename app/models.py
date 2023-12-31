from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user
from flask import has_app_context, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging, sys

db = SQLAlchemy()

user_ip_mapping = db.Table('user_ip_mapping',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('ip_location_id', db.Integer, db.ForeignKey('ip_location.id'), primary_key=True)
)


class SignInData(db.Model):
    # Database model for SignInData
    id = db.Column(db.Integer, primary_key=True)
    l_number = db.Column(db.String, nullable=False)
    lab_location = db.Column(db.String, nullable=False)
    class_selected = db.Column(db.String, nullable=False)
    sign_in_timestamp = db.Column(db.DateTime, nullable=False)
    sign_out_timestamp = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    sign_in_comments = db.Column(db.Text, nullable=True)
    ip_location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'))


class User(UserMixin, db.Model):
    # Database model for User
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    ip_locations = db.relationship('IPLocation', secondary=user_ip_mapping, lazy='subquery',
                                   backref=db.backref('mapped_users', lazy=True))

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)


class IPLocation(db.Model):
    # Database model for storing IPLocation
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45))
    location_name = db.Column(db.String(100))
    sign_ins = db.relationship('SignInData', backref='ip_location', lazy='dynamic')
    email_template = db.relationship('EmailTemplate', backref='ip_location', uselist=False, cascade='all, delete-orphan')
    welcome_email_enabled = db.Column(db.Boolean, default=False, nullable=False)
    custom_email = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return f'<IPLocation {self.ip_address} - {self.location_name}>'


class TermDates(db.Model):
    __tablename__ = 'term_dates'

    id = db.Column(db.Integer, primary_key=True)
    term_name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)


class LabMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))
    lab_location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'))
    lab_location = db.relationship('IPLocation', backref=db.backref('lab_messages', cascade='all, delete-orphan'))


class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    lab_location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'))


class ManualSignInSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'), nullable=False)
    manual_signin_enabled = db.Column(db.Boolean, default=False)
    l_numbers_csv = db.Column(db.Text)  # Storing L-numbers as a CSV string
    class_options = db.Column(db.Text)  # Storing class options as a comma-separated string

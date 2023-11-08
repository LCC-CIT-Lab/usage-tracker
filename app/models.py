from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()


class SignInData(db.Model):
    # Database model for SignInData
    id = db.Column(db.Integer, primary_key=True)
    l_number = db.Column(db.String, nullable=False)
    lab_location = db.Column(db.String, nullable=False)
    class_selected = db.Column(db.String, nullable=False)
    sign_in_timestamp = db.Column(db.DateTime, nullable=False)
    sign_out_timestamp = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    ip_location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'))


class User(UserMixin, db.Model):
    # Database model for User
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_default_password = db.Column(db.Boolean, default=True, nullable=False)
    can_set_message = db.Column(db.Boolean, default=False)
    can_access_query_selection = db.Column(db.Boolean, default=False)
    ip_location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'))

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
    lab_location_id = db.Column(db.Integer, db.ForeignKey('ip_location.id'), nullable=False)  # Corrected this line
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    lab_location = db.relationship('IPLocation', backref=db.backref('messages', lazy=True))  # Corrected this line
    user = db.relationship('User', backref=db.backref('messages', lazy=True))
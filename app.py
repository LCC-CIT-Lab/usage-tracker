from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import SignatureExpired, BadSignature, URLSafeTimedSerializer as Serializer
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from io import StringIO


import csv
import toml
import os
import subprocess

# Generate a key for Fernet
KEY = Fernet.generate_key()

# Load configurations from config.toml
config = toml.load('config.toml')

# Generate an initial password to reset
DEFAULT_ADMIN_PASSWORD_HASH = generate_password_hash(config['encryption']['DEFAULT_ADMIN_PASSWORD'])

# Start Flask app
app = Flask(__name__)
app.secret_key = Fernet.generate_key()


# Apply configurations to Flask app
app.config.from_mapping(config['flask'])

db = SQLAlchemy(app)


# Database Model
class SignInData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    l_number = db.Column(db.String, nullable=False)  # Remove unique=True
    lab_location = db.Column(db.String, nullable=False)
    class_selected = db.Column(db.String, nullable=False)
    sign_in_timestamp = db.Column(db.DateTime, nullable=False)
    sign_out_timestamp = db.Column(db.DateTime, nullable=True)
    comments = db.Column(db.Text, nullable=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_default_password = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)


# Initialize the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def get_student_classes(l_number):
    """Retrieve the classes a student is enrolled in using the TSV files."""
    class_ids = []
    with open('studentsinclasses.tsv', 'r') as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            if l_number == row[0]:  # Check if L number matches
                class_ids.append(row[1])  # Add class ID

    classes = []
    with open('classes.tsv', 'r') as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            if row[1] in class_ids:  # Check if class ID matches
                class_name = row[2] + " " + row[3] + ": " + row[4]
                classes.append(class_name)

    return list(set(classes))


has_run = False


@app.before_request
def before_request():
    global has_run
    if not has_run:
        create_admin()
        has_run = True


def create_admin():
    db.create_all()  # Ensure the database tables are created
    admin_username = 'admin'  # Replace with desired admin username
    admin_email = 'rosenauj@my.lanecc.edu'  # Replace with the admin email
    default_admin_password = config['encryption']['DEFAULT_ADMIN_PASSWORD']

    existing_admin = User.query.filter_by(username=admin_username).first()
    if not existing_admin:
        # Create an admin user with a default password
        admin_user = User(
            username=admin_username,
            email=admin_email,
            is_admin=True
        )
        admin_user.set_password(default_admin_password)
        db.session.add(admin_user)
        db.session.commit()


@app.route('/', methods=['GET', 'POST'])
def landing():
    if request.method == 'POST':
        l_number = request.form.get('l_number')
        valid_l_number = False
        with open('students.tsv', 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if l_number == row[0]:
                    valid_l_number = True
                    break

        if not valid_l_number:
            flash('Invalid L number, please sign-in again.')
            return redirect(url_for('landing'))

        yesterday = (datetime.now() - timedelta(days=1)).date()
        students_signed_in_yesterday = SignInData.query.filter(SignInData.sign_in_timestamp <= yesterday,
                                                               SignInData.sign_out_timestamp.is_(None)).all()
        for student in students_signed_in_yesterday:
            student.sign_out_timestamp = datetime.now()
        db.session.commit()

        # Check if student is already signed in today
        today = datetime.now().date()
        student_entries_today = SignInData.query.filter_by(l_number=l_number).all()

        # Find the latest entry from today (if any)
        student_today = None
        for entry in sorted(student_entries_today, key=lambda x: x.sign_in_timestamp, reverse=True):
            if entry.sign_in_timestamp.date() == today and not entry.sign_out_timestamp:
                student_today = entry
                break

        if student_today and not student_today.sign_out_timestamp:
            # If student is already signed in today and hasn't signed out, sign them out
            student_today.sign_out_timestamp = datetime.now()
            db.session.commit()
            app.logger.info('Student already signed in today. Signing them out.')
            return redirect(url_for('checkout', l_number=l_number))

        classes = get_student_classes(l_number)
        return redirect(url_for('sign_in', l_number=l_number, **{'classes[]': classes}))

    return render_template('landing.html')


@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        l_number = request.form.get('l_number')
        app.logger.info(f"Received L number: {l_number}")

        # Check if student is already signed in today
        today = datetime.now().date()
        student_entries_today = SignInData.query.filter_by(l_number=l_number).all()

        # Find the latest entry from today (if any)
        student_today = None
        for entry in sorted(student_entries_today, key=lambda x: x.sign_in_timestamp, reverse=True):
            if entry.sign_in_timestamp.date() == today and not entry.sign_out_timestamp:
                student_today = entry
                break

        if student_today and not student_today.sign_out_timestamp:
            # If student is already signed in today and hasn't signed out, sign them out
            student_today.sign_out_timestamp = datetime.now()
            db.session.commit()
            app.logger.info('Student already signed in today. Signing them out.')
            return redirect(url_for('landing'))

        lab_location = request.form.get('lab_location')
        class_selected = request.form.get('class_selected')

        sign_in_data = SignInData(
            l_number=l_number,
            lab_location=lab_location,
            class_selected=class_selected,
            sign_in_timestamp=datetime.now()
        )

        db.session.add(sign_in_data)
        db.session.commit()
        app.logger.info('Signed in successfully')
        return redirect(url_for('landing'))

    l_number = request.args.get('l_number')
    classes = request.args.getlist('classes[]')
    app.logger.info(f'l_number = {l_number}')  # Log the value of l_number
    app.logger.info(f'classes = {classes}')  # Log the value of classes
    if not l_number or not classes:
        app.logger.warning('Invalid parameters provided.')
        return redirect(url_for('landing'))

    return render_template('sign_in.html', classes=classes, l_number=l_number)


@app.route('/sign-out', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        comment = request.form.get('comment')
        l_number = request.form.get('l_number')

        # Send the comment
        send_comment_to_support(l_number, comment)

        return redirect(url_for('landing'))

    l_number = request.args.get('l_number')
    if not l_number:
        return redirect(url_for('landing'))
    return render_template('sign_out.html', l_number=l_number)


def send_comment_to_support(l_number, comment):
    try:
        # Email details
        email = config['smtp']['SUPPORT_EMAIL']  # The email address that will receive the comment
        subject = "CIT Lab User Comment"
        body = f"Comment from L Number {l_number}:\n\n{comment}\n\nThank you,\n The Sign-in Form"

        # Create the email message
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = config['smtp']['SUPPORT_EMAIL']  # assuming this is in your config
        msg['To'] = email

        # Write the email to a file
        with open('email.txt', 'w') as file:
            file.write(msg.as_string())

        # Send the email using msmtp
        command = f"cat email.txt | msmtp --account={config['smtp']['ACCOUNT']} -t"
        process = subprocess.Popen(command, shell=True)
        process.communicate()

        # Optionally, remove the email file after sending
        os.remove('email.txt')

    except Exception as e:
        print(f"Failed to send email: {e}")


def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message.decode()


def decrypt_message(encrypted_message, key):
    cipher = Fernet(key)
    decrypted_message = cipher.decrypt(encrypted_message.encode()).decode()
    return decrypted_message


def generate_token(username, expiration=1800):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'username': username}).decode('utf-8')


def validate_token(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None  # valid token, but expired
    except BadSignature:
        return None  # invalid token
    return data.get('username')


def confirm_token(token, expiration=1800):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=expiration)
    except:
        return False
    return data['username']


@app.route('/query_selection', methods=['GET', 'POST'])
@login_required
def query_selection():
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        # Fetch data from DB, create CSV and send email
        data = SignInData.query.filter(SignInData.sign_in_timestamp.between(start_date, end_date)).all()
        send_data_as_csv(current_user.email, data)  # Use the current user's email from the user session

    # If it's a GET request or the POST request is processed, show the same query selection page
    return render_template('query_selection.html')


def send_email_to_user(email, link):
    try:
        # Create the email message
        subject = "LCC Query UI Access"
        body = f"Dear User,\n\nPlease use the following link to access the Query UI:\n\n{link}\n\nThank you,\nLCC Support"
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = config['smtp']['SUPPORT_EMAIL']  # assuming this is still in your config
        msg['To'] = email

        # Write the email to a file
        with open('email.txt', 'w') as file:
            file.write(msg.as_string())

        # Send the email using msmtp
        command = f"cat email.txt | msmtp --account={config['smtp']['ACCOUNT']} -t"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Print any output from msmtp
        if stdout:
            print("Output:", stdout.decode())
        if stderr:
            print("Error:", stderr.decode())

        # Optionally, remove the email file after sending
        os.remove('email.txt')

    except Exception as e:
        print(f"Failed to send email: {e}")


def send_data_as_csv(email, data):
    # Convert data to CSV format
    output = StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(
        ["L Number", "Lab Location", "Class Selected", "Sign-in Timestamp", "Sign-out Timestamp", "Comments"])

    # Write data
    for entry in data:
        writer.writerow([entry.l_number, entry.lab_location, entry.class_selected, entry.sign_in_timestamp,
                         entry.sign_out_timestamp, entry.comments])

    # Reset the pointer of the StringIO object to the beginning
    output.seek(0)

    # Create the email message
    msg = MIMEMultipart()
    msg['Subject'] = "Attendance Data"
    msg['From'] = config['smtp']['SUPPORT_EMAIL']
    msg['To'] = email

    # Attach the body text to the email
    body = "Attached is the attendance data for the specified date range."
    msg.attach(MIMEText(body, 'plain'))

    # Attach the CSV data
    attachment = MIMEText(output.getvalue(), 'plain', 'utf-8')
    attachment['Content-Disposition'] = 'attachment; filename="attendance_data.csv"'
    msg.attach(attachment)

    # Write the email to a file
    with open('email_with_attachment.txt', 'w') as file:
        file.write(msg.as_string())

    # Send the email using msmtp
    command = f"cat email_with_attachment.txt | msmtp --account={config['smtp']['ACCOUNT']} -t"
    process = subprocess.Popen(command, shell=True)
    process.communicate()

    # Optionally, remove the email file after sending
    os.remove('email_with_attachment.txt')


@app.route('/check-db')
def check_db():
    data = SignInData.query.all()
    output = "Database Records:<br>"
    for entry in data:
        output += f"L Number: {entry.l_number}, Lab: {entry.lab_location}, Class: {entry.class_selected}, Sign In: {entry.sign_in_timestamp}, Sign Out: {entry.sign_out_timestamp}<br>"
    return output


# Add near the other routes in app.py
@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            # Generate a password reset token
            reset_token = generate_token(username)
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_password_reset_email(user.email, reset_link)
            flash('Password reset email sent.')
            return redirect(url_for('landing'))
    return render_template('request_password_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['password']
        username = validate_token(token)
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                user.set_password(new_password)
                db.session.commit()
                flash('Your password has been updated.')
                return redirect(url_for('landing'))
            else:
                flash('Invalid user.')
                return redirect(url_for('landing'))
        else:
            flash('Invalid or expired token.')
            return redirect(url_for('landing'))
    return render_template('reset_password.html', token=token)


def send_password_reset_email(user_email):
    try:
        # Generate a password reset token
        reset_token = generate_token(user_email)
        reset_url = url_for('reset_password', token=reset_token, _external=True)

        # Email details
        subject = "Set Your Admin Password"
        sender = config['smtp']['SUPPORT_EMAIL']
        body = f"""
        Hi,

        To reset your password, click on the following link: {reset_url}

        If you did not make this request then simply ignore this email.

        Best,
        Your Support Team
        """

        # Create the email message
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = user_email

        # Write the email to a file
        with open('password_reset_email.txt', 'w') as file:
            file.write(msg.as_string())

        # Send the email using msmtp
        command = f"cat password_reset_email.txt | msmtp --account={config['smtp']['ACCOUNT']} -t"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Optionally, log or print any output from msmtp
        if stdout:
            app.logger.info(stdout.decode())
        if stderr:
            app.logger.error(stderr.decode())

        # Optionally, remove the email file after sending
        os.remove('password_reset_email.txt')

    except Exception as e:
        app.logger.error(f"Failed to send password reset email: {e}")


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have access to this page.')
        return redirect(url_for('landing'))

    if request.method == 'POST':
        # Check if we are adding a new user
        if 'add' in request.form:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            is_admin = 'is_admin' in request.form

            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('User already exists.')
            else:
                new_user = User(username=username, email=email, is_admin=is_admin)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('New user added.')

        # Check if we are removing a user
        elif 'remove' in request.form:
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User removed.')

    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            # Redirect to query_selection if the user is not an admin
            return redirect(url_for('query_selection') if not user.is_admin else url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied: You do not have admin privileges.')
        return redirect(url_for('landing'))  # Redirect to a general page if not admin
    # Admin logic here
    return render_template('admin_dashboard.html')  # Render the admin dashboard page


@app.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('A user with this email already exists.')
            else:
                # Create a new user with a default password
                new_user = User(email=email)
                new_user.set_password(config['encryption']['DEFAULT_ADMIN_PASSWORD'])
                db.session.add(new_user)
                db.session.commit()

                # Generate a password reset token
                reset_token = generate_token(new_user.username)
                reset_url = url_for('reset_password', token=reset_token, _external=True)

                # Send an email to the user with the reset URL
                send_password_reset_email(new_user.email, reset_url)
                flash('User created. A password reset email has been sent.', 'success')
        else:
            flash('Please enter an email address.', 'error')

    users = User.query.all()
    return render_template('user_management.html', users=users)


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

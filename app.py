from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from io import StringIO

import csv
import toml
import os
import subprocess

# Generate a key for Fernet
KEY = Fernet.generate_key()

# Load configurations from config.toml
config = toml.load('config.toml')

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


def generate_token(email):
    today = datetime.now()
    message = f"{email}-{today.month}-{today.day}"
    return encrypt_message(message, KEY)


def validate_token(token):
    if not token:
        return None

    decrypted_message = decrypt_message(token, KEY)
    email, month, day = decrypted_message.split('-')
    today = datetime.now()
    if int(month) == today.month and int(day) == today.day:
        return email  # Return the email if the token is valid
    else:
        return None  # Return None if the token is expired


@app.route('/query_login', methods=['GET', 'POST'])
def query_login():
    if request.method == 'POST':
        email = request.form['email']
        if email == config['encryption']['VALID_EMAILS']:
            token = generate_token(email)
            link = url_for('query_selection', token=token, _external=True)
            send_email_to_user(email, link)  # Use your email sending function
            flash('Login email sent.')
            return redirect(url_for('query_login'))
    return render_template('query_login.html')


@app.route('/query_selection', methods=['GET', 'POST'])
def query_selection():
    if request.method == 'GET':
        token = request.args.get('token')
        email = validate_token(token)
        if not email:
            flash('Invalid or expired token.')
            return redirect(url_for('landing'))

        # Store the validated email in the session
        session['email_for_query'] = email

    elif request.method == 'POST':
        email = session.get('email_for_query')
        if not email:
            flash('Session expired or invalid. Please login again.')
            return redirect(url_for('query_login'))

        start_date = request.form['start_date']
        end_date = request.form['end_date']
        # Fetch data from DB, create CSV and send email
        data = SignInData.query.filter(SignInData.sign_in_timestamp.between(start_date, end_date)).all()
        send_data_as_csv(email, data)  # Implement this function

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


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

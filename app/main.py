from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
from flask_wtf.csrf import CSRFError
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, time, timedelta
from email.mime.text import MIMEText
from app.models import db, SignInData, IPLocation, TermDates, LabMessage, ManualSignInSettings
from app.forms import LandingForm, SignInForm, SignOutForm, HoursInputForm
from app.utils import get_lab_info
from paramiko import util
from .config import load_config
from fs.sshfs import SSHFS
from sqlalchemy import func, extract
from collections import defaultdict


import calendar
import numpy as np
import subprocess
import os
import csv
import paramiko
import logging

main_bp = Blueprint('main', __name__)

config = load_config()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def generate_csrf_token(secret_key):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps({})  # Empty dict as the payload


def validate_csrf_token(token, secret_key, max_age=3600):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        serializer.loads(token, max_age=max_age)
        return True
    except BadSignature:
        return False


@main_bp.route('/', methods=['GET', 'POST'])
def landing():
    form = LandingForm()
    lab_id = request.args.get('lab_id')
    lab_location_name = get_lab_name(request.remote_addr)
    lab_info = get_lab_info(request.remote_addr) if not lab_id else (lab_location_name, lab_id)
    lab_id = lab_info[1] if lab_info else None
    lab_location = None  # Initialize lab_location

    if lab_id and is_valid_lab_id(lab_id):
        lab_location = IPLocation.query.get(lab_id)
        messages = lab_location.lab_messages if lab_location else None
    else:
        messages = None

    # Count currently signed in users for this lab location
    sign_in_count = current_sign_ins(lab_id)
    current_app.logger.info(f"current sign ins {sign_in_count}.")

    try:
        if form.validate_on_submit():
            l_number = form.l_number.data

            # Load manual sign-in settings from database
            settings = ManualSignInSettings.query.first()

            if settings and settings.manual_signin_enabled:
                l_numbers_list = parse_csv_to_list(settings.l_numbers_csv)
                if not l_numbers_list or l_number in l_numbers_list:
                    session['l_number'] = l_number
                    action = choosesignout(l_number)
                else:
                    flash('Invalid L number, please sign-in again.')
                    return render_template('landing.html', form=form, lab_location=lab_location, lab_location_name=lab_location_name, lab_id=lab_id, messages=messages, sign_in_count=sign_in_count)
            else:
                l_number = normalize_l_number(l_number)
                if student_exists(l_number):
                    session['l_number'] = l_number
                    action = choosesignout(l_number)
                else:
                    flash('Invalid L number, please sign-in again.')
                    return render_template('landing.html', form=form, lab_location=lab_location, lab_location_name=lab_location_name, lab_id=lab_id, messages=messages, sign_in_count=sign_in_count)

            # Check if it's the first visit
            first_visit = SignInData.query.filter_by(l_number=l_number).count() == 0
            if first_visit and lab_location and lab_location.welcome_email_enabled:
                send_welcome_email(l_number, lab_id)
                current_app.logger.info(f"Sending welcome email to {l_number}.")

            if action == 'sign_out':
                return redirect(url_for('main.sign_out', l_number=l_number))
            else:
                return redirect(url_for('main.sign_in', l_number=l_number))
            
        return render_template('landing.html', form=form, lab_location=lab_location, lab_location_name=lab_location_name, lab_id=lab_id, messages=messages, sign_in_count=sign_in_count)
    
    except CSRFError as e:
        flash('Session has expired. Please refresh the page.', 'warning')
        return redirect(url_for('main.landing'))


def parse_csv_to_list(csv_string):
    """
    Parses a CSV string into a list.
    """
    if not csv_string:
        return []
    return [item.strip() for item in csv_string.split(',')]


def choosesignout(l_number):
    today = datetime.now().date()
    student_today = SignInData.query.filter(
        SignInData.l_number == l_number,
        db.func.date(SignInData.sign_in_timestamp) == today,
        SignInData.sign_out_timestamp.is_(None)
    ).first()

    if student_today:
        return 'sign_out'
    else:
        return 'sign_in'


def is_valid_lab_id(lab_id):
    try:
        int(lab_id)
        return True
    except ValueError:
        flash('Invalid lab ID', 'error')
        return False


def get_latest_lab_message(lab_id):
    return LabMessage.query.filter_by(lab_location_id=lab_id).order_by(LabMessage.timestamp.desc()).first()


def normalize_l_number(l_number):
    l_number = l_number.upper()
    return f'L{l_number}' if not l_number.startswith('L') else l_number


def handle_student_sign_in(l_number, lab_id):
    classes = get_student_classes(l_number)
    classes_param = ",".join(classes)  # Join class names with a comma
    return redirect(url_for('main.sign_in', l_number=l_number, lab_id=lab_id, classes=classes_param))


def create_sshfs():
    current_app.logger.debug("Loading private key for SSHFS.")
    pkey = paramiko.RSAKey.from_private_key_file(config['sshfs']['PRIVATE_KEY_PATH'])

    current_app.logger.debug("Creating SSHFS instance.")
    sshfs = SSHFS(
        host=config['sshfs']['HOST'],
        user=config['sshfs']['USER'],
        pkey=pkey,
        port=config['sshfs']['PORT'],
    )
    current_app.logger.debug("SSHFS instance created successfully.")
    return sshfs


@main_bp.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    form = SignInForm()
    lab_location_name = 'Unknown Location'

    # Extract lab information
    lab_info = get_lab_info(request.remote_addr)
    lab_location_name = lab_info[0] if lab_info else 'Unknown Location'
    lab_id = lab_info[1] if lab_info else None

    # Fetch manual sign-in settings from database
    settings = ManualSignInSettings.query.filter_by(location_id=lab_id).first()

    # Determine classes to display based on settings
    if settings and settings.manual_signin_enabled:
        manual_class_options = settings.class_options.split(',')
        classes = manual_class_options
    else:
        classes = get_student_classes(session.get('l_number', ''))

    # Ensure "Other" is always included in the class list
    classes.append('Other')
    form.class_selected.choices = [(cls, cls) for cls in classes]

    l_number = request.args.get('l_number') or session.get('l_number')
    if l_number:
        # Check for unfinished session
        unfinished_session = SignInData.query.filter_by(
            l_number=l_number,
            sign_out_timestamp=None
        ).first()
        if unfinished_session:
            # Redirect to input hours page
            return redirect(url_for('main.input_hours', l_number=l_number))

        form.l_number.data = l_number
        form.l_number.render_kw = {'readonly': True}

    if form.validate_on_submit():
        class_selected = form.class_selected.data

        last_sign_in = SignInData.query.filter_by(l_number=l_number).order_by(
            SignInData.sign_in_timestamp.desc()).first()
        if last_sign_in and not last_sign_in.sign_out_timestamp:
            return redirect(url_for('main.input_hours', l_number=l_number))

        sign_in_comment = form.sign_in_comment.data

        # Handle sign-in logic
        process_sign_in(l_number, lab_location_name, class_selected, lab_id, sign_in_comment)
        flash('Signed in successfully')
        return redirect(url_for('main.landing'))

    return render_template('sign_in.html', form=form, lab_location_name=lab_location_name)


@main_bp.route('/input_hours/<l_number>', methods=['GET', 'POST'])
def input_hours(l_number):
    form = HoursInputForm()
    if form.validate_on_submit():
        hours = form.hours.data
        # Fetch the latest sign-in record for l_number
        last_sign_in = SignInData.query.filter_by(
            l_number=l_number
        ).order_by(SignInData.sign_in_timestamp.desc()).first()

        if last_sign_in:
            # Calculate and set the sign-out timestamp
            last_sign_in.sign_out_timestamp = last_sign_in.sign_in_timestamp + timedelta(hours=hours)
            db.session.commit()
            flash('Hours updated successfully.')
            return redirect(url_for('main.sign_in'))

    return render_template('input_hours.html', form=form, l_number=l_number)


@main_bp.route('/sign-out', methods=['GET', 'POST'])
def sign_out():
    form = SignOutForm()
    l_number = request.args.get('l_number') or session.get('l_number')
    continue_without_comment = request.args.get('continue')  # Check if continue was clicked

    # Ensure l_number is available
    if not l_number:
        flash('Error: L number missing.')
        return redirect(url_for('main.landing'))

    # Calculate daily time in lab and total term time
    daily_time = calculate_daily_time_in_lab(l_number)
    total_term_time = calculate_total_term_time(l_number)

    if form.validate_on_submit():
        # Handle form submission with a comment
        process_sign_out(l_number, form.comment.data)
        flash('Signed out successfully.')
    elif continue_without_comment:
        # Handle clicking continue without a comment
        process_sign_out(l_number, None)
        flash('Signed out successfully.')
    else:
        # If neither form submission nor continue button click
        return render_template('sign_out.html', form=form, l_number=l_number, daily_time=daily_time, total_term_time=total_term_time)

    session.pop('l_number', None)
    return redirect(url_for('main.landing'))


def process_sign_out(l_number, comment):
    sign_in_record = SignInData.query.filter_by(l_number=l_number, sign_out_timestamp=None).order_by(SignInData.sign_in_timestamp.desc()).first()

    if sign_in_record:
        current_app.logger.info(f"{l_number} sign-out")
        sign_in_record.sign_out_timestamp = datetime.now()
        sign_in_record.comments = comment if comment else ""
        if comment:  # Send email only if comment is provided
            try:
                lab_location = IPLocation.query.get(sign_in_record.ip_location_id)
                recipient_email = lab_location.custom_email if lab_location.custom_email else current_app.config['smtp']['SUPPORT_EMAIL']
                send_comment_to_support(l_number, comment, recipient_email)
            except Exception as e:
                current_app.logger.error('Problem with sending comment to support')
        try:
            db.session.commit()
            current_app.logger.info('User signed out successfully')
            return True
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Error during sign out for L number {l_number}: {e}')
            return False
    else:
        current_app.logger.error(f"No sign-in record found for L number {l_number}")
        return False


@main_bp.route('/auto_sign_out')
def auto_sign_out():
    l_number = request.args.get('l_number')

    if not l_number:
        flash('Error: L number missing.')
        return redirect(url_for('main.landing'))

    # Process the sign-out
    process_sign_out(l_number, "")
    flash('Signed out automatically due to inactivity.')
    session.pop('l_number', None)  # Clear the session

    return redirect(url_for('main.landing'))


def calculate_daily_time_in_lab(l_number):
    today = datetime.now().date()
    records = SignInData.query.filter(
        SignInData.l_number == l_number,
        db.func.date(SignInData.sign_in_timestamp) == today
    ).all()
    return sum(
        ((record.sign_out_timestamp or datetime.now()) - record.sign_in_timestamp).total_seconds() / 3600
        for record in records
    )


def calculate_total_term_time(l_number):
    current_term = get_current_term()
    if current_term:
        records = SignInData.query.filter(
            SignInData.l_number == l_number,
            SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date)
        ).all()
        return sum(
            ((record.sign_out_timestamp or record.sign_in_timestamp) - record.sign_in_timestamp).total_seconds() / 3600
            for record in records
        )
    return 0


def student_exists(l_number):
    """Check if the student exists in the TSV file."""
    local_file_path = current_app.config['sshfs']['LOCAL_STUDENT_FILE']
    try:
        # Try reading the file locally
        with open(local_file_path, 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            return any(l_number == row[0] for row in reader)
    except FileNotFoundError:
        current_app.logger.error(f'Local file {local_file_path} not found, trying SSHFS')

    # SSHFS part
    sshfs = create_sshfs()
    if sshfs is not None:
        try:
            with sshfs.open(os.path.join(config['sshfs']['REMOTE_TSV_PATH'], local_file_path), 'r') as file:
                reader = csv.reader(file, delimiter='\t')
                return any(l_number == row[0] for row in reader)
        except Exception as e:
            current_app.logger.error(f"Error reading file over SSHFS: {e}")

    return False


def get_student_today(l_number):
    """Get the most recent sign-in record for the student for today."""
    today = datetime.now().date()
    return SignInData.query.filter(
        SignInData.l_number == l_number,
        db.func.date(SignInData.sign_in_timestamp) == today,
        SignInData.sign_out_timestamp.is_(None)
    ).order_by(SignInData.sign_in_timestamp.desc()).first()


def get_lab_name(ip_address):
    """Retrieve lab location based on the user's IP address."""
    ip_location = IPLocation.query.filter_by(ip_address=ip_address).first()
    if ip_location:
        return ip_location.location_name
    return "Unknown Location"


def student_signed_in_today(l_number):
    """Check if the student is already signed in today."""
    return get_student_today(l_number) is not None


def process_sign_in(l_number, lab_location_name, class_selected, lab_id, sign_in_comment):
    sign_in_data = SignInData(
        l_number=l_number,
        lab_location=lab_location_name,
        class_selected=class_selected,
        ip_location_id=lab_id,
        sign_in_timestamp=datetime.now(),
        sign_in_comments=sign_in_comment,
    )

    db.session.add(sign_in_data)
    try:
        db.session.commit()

        lab_location = IPLocation.query.get(lab_id)
        if sign_in_comment:
            recipient_email = lab_location.custom_email if lab_location.custom_email else current_app.config['smtp']['SUPPORT_EMAIL']
        if lab_id and lab_location.custom_email:
            send_sign_in_comment_email(l_number, sign_in_comment, recipient_email)

        flash('Signed in successfully')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Error processing sign in for L number {l_number}: {e}')
        flash('An error occurred during sign in.', 'error')

    return redirect(url_for('main.landing'))


def handle_existing_sign_in(l_number):
    """Handle the case where the student is already signed in."""
    student_today = get_student_today(l_number)
    if student_today:
        student_today.sign_out_timestamp = datetime.now()
        db.session.commit()
        flash('You have already signed in today. Signing you out.')
    return redirect(url_for('main.sign_out', l_number=l_number))


def handle_sign_in_error(e):
    """Handle errors that occur during sign-in."""
    db.session.rollback()
    current_app.logger.error(f'Error signing in: {e}')
    flash('An error occurred while signing in.', 'error')
    return redirect(url_for('main.landing'))


def redirect_with_flash(message, category, endpoint):
    """Redirect to a given endpoint with a flashed message."""
    flash(message, category)
    return redirect(url_for(endpoint))


def get_student_classes(l_number):
    """Retrieve the classes a student is enrolled in."""
    class_ids = []
    classes = []
    local_file_path = current_app.config['sshfs']['LOCAL_STUCLASS_FILE']
    local_file_path_classes = current_app.config['sshfs']['LOCAL_CLASS_FILE']

    try:
        # Read student's class IDs from local file
        with open(local_file_path, 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if l_number.strip('"') == row[0].strip('"'):
                    class_ids.append(row[1].strip('"'))

        # Read class names from local file
        with open(local_file_path_classes, 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if row[1].strip('"') in class_ids:
                    class_name = f"{row[2]} {row[3]}: {row[4]}"
                    classes.append(class_name)
    except FileNotFoundError:
        current_app.logger.error(f'Local file {local_file_path} or {local_file_path_classes} not found, trying SSHFS')

        sshfs = create_sshfs()
        if sshfs is not None:
            try:
                # SSHFS part for class IDs
                with sshfs.open(os.path.join(config['sshfs']['REMOTE_TSV_PATH'], local_file_path), 'r') as file:
                    reader = csv.reader(file, delimiter='\t')
                    for row in reader:
                        if l_number.strip('"') == row[0].strip('"'):
                            class_ids.append(row[1].strip('"'))

                # SSHFS part for class names
                with sshfs.open(os.path.join(config['sshfs']['REMOTE_TSV_PATH'], local_file_path_classes), 'r') as file:
                    reader = csv.reader(file, delimiter='\t')
                    for row in reader:
                        if row[1].strip('"') in class_ids:
                            class_name = f"{row[2]} {row[3]}: {row[4]}"
                            classes.append(class_name)
            except Exception as e:
                current_app.logger.error(f"Error reading file over SSHFS: {e}")
                return []

    return list(set(classes))


@main_bp.route('/download_csv/<filename>')
def download_csv(filename):
    # Make sure the filename is safe to open
    if not os.path.basename(filename) == filename:
        redirect("400.html", 400)

    csv_path = os.path.join('/tmp', filename)
    if os.path.exists(csv_path):
        return send_from_directory('/tmp', filename, as_attachment=True)
    else:
        flash('No CSV data found. Please generate the report again.', 'error')
        return redirect(url_for('admin.query_selection'))


def current_sign_ins(lab_id):
    today = datetime.now().date()
    count = SignInData.query.filter(
        SignInData.ip_location_id == lab_id,
        func.date(SignInData.sign_in_timestamp) == today,
        SignInData.sign_out_timestamp.is_(None)
    ).count()
    return count


def send_comment_to_support(l_number, comment, recipient_email):
    email_file_path = current_app.config['smtp']['EMAIL_FILE_PATH']  # Use a full path, e.g., in /tmp

    try:
        # Email details
        email = recipient_email
        subject = "CIT Lab User Comment"
        body = f"Comment from L Number {l_number}:\n\n{comment}\n\nThank you,\n The Sign-in Form"

        # Create the email message
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = current_app.config['smtp']['SUPPORT_EMAIL']
        msg['To'] = email

        # Write the email to a file
        with open(email_file_path, 'w') as file:
            file.write(msg.as_string())

        # Send the email using msmtp
        command = f"cat {email_file_path} | msmtp --account={config['smtp']['ACCOUNT']} -t"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            raise Exception(f"msmtp failed: {stderr.decode().strip()}")

        current_app.logger.info("Email sent successfully")
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {e}")

    finally:
        # Clean up: remove the email file
        if os.path.exists(email_file_path):
            os.remove(email_file_path)


def send_sign_in_comment_email(l_number, comment, recipient_email):
    subject = "Sign-In Comment from " + l_number
    body = f"Comment from L Number {l_number} at sign-in:\n\n{comment}"
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = current_app.config['smtp']['SUPPORT_EMAIL']
    msg['To'] = recipient_email

    try:
        with open('/tmp/email.txt', 'w') as file:
            file.write(msg.as_string())
        subprocess.run(["msmtp", "-a", current_app.config['smtp']['ACCOUNT'], recipient_email], input=msg.as_string(), text=True)
        current_app.logger.info("Sign-in comment email sent successfully")
    except Exception as e:
        current_app.logger.error(f"Failed to send sign-in comment email: {e}")


@main_bp.route('/check-db')
def check_db():
    data = SignInData.query.all()
    output = "Database Records:<br>"
    for entry in data:
        output += f"L Number: {entry.l_number}, Lab: {entry.lab_location}, Class: {entry.class_selected}, Sign In: {entry.sign_in_timestamp}, Sign Out: {entry.sign_out_timestamp}<br>"
    return output


def get_current_term():
    current_date = datetime.now().date()
    current_term = TermDates.query.filter(TermDates.start_date <= current_date, TermDates.end_date >= current_date).first()
    return current_term


def default_sign_out(sign_in_timestamp):
    return datetime.combine(sign_in_timestamp.date(), time(16, 30))


@main_bp.route('/statistics')
def statistics():
    lab_id = request.args.get('lab_id')
    lab_location_name = get_lab_name(request.remote_addr)

    if lab_id and is_valid_lab_id(lab_id):
        try:
            stats = enhanced_student_stats(lab_id)
            if not stats:
                raise ValueError("Stats data is empty or not properly set")
            return render_template('statistics.html', stats=stats, lab_id=lab_id, lab_location_name=lab_location_name)
        except Exception as e:
            current_app.logger.error(f"Error generating stats: {e}")
            flash('Error generating statistics', 'error')
            return redirect(url_for('main.landing'))
    else:
        flash('Invalid lab ID', 'error')
        return redirect(url_for('main.landing'))


def enhanced_student_stats(lab_id):
    # Ensure lab_id is valid
    if not lab_id:
        current_app.logger.debug("Invalid lab_id provided.")
        return None

    # Define the current term
    current_term = TermDates.query.filter(
        TermDates.start_date <= datetime.now().date(),
        TermDates.end_date >= datetime.now().date()
    ).first()
    if not current_term:
        current_app.logger.debug("No current term found.")
        flash('Please create a current term to access statistics.')
        return None

    # Initialize stats dictionary
    stats = {
        "total_hours": 0,
        "average_session_duration": 0,
        "std_deviation": 0,
        "variance": 0,
        "median": 0,
        "peak_hour": None,
        "busiest_day": None,
        "new_students": 0,
        "returning_students": 0,
        "most_popular_class": None,
        "hourly_attendance": [],
        "daily_attendance": []
    }

    # Basic stats
    sign_ins = SignInData.query.filter(
        SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date),
        SignInData.ip_location_id == lab_id
    ).all()

    if sign_ins:
        total_hours = sum(
            ((sign_out.sign_out_timestamp or datetime.now()) - sign_out.sign_in_timestamp).total_seconds() / 3600
            for sign_out in sign_ins
        )
        stats["total_hours"] = round(total_hours, 2)
        stats["average_session_duration"] = round(total_hours / len(sign_ins), 2) if len(sign_ins) > 0 else 0

        # Advanced statistics calculations
        session_durations = [
            ((sign_out.sign_out_timestamp or datetime.now()) - sign_out.sign_in_timestamp).total_seconds() / 3600
            for sign_out in sign_ins
        ]
        stats["std_deviation"] = round(np.std(session_durations), 2)
        stats["variance"] = round(np.var(session_durations), 2)
        stats["median"] = round(np.median(session_durations), 2)

        # Peak hour calculation
        peak_hour_query = db.session.query(
            extract('hour', SignInData.sign_in_timestamp).label('hour'),
            func.count(SignInData.id)
        ).filter(
            SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date),
            SignInData.ip_location_id == lab_id
        ).group_by('hour').order_by(func.count(SignInData.id).desc()).first()

        stats["peak_hour"] = peak_hour_query.hour if peak_hour_query else None

        # Busiest day calculation
        busiest_day_query = db.session.query(
            extract('dow', SignInData.sign_in_timestamp).label('dow'),
            func.count(SignInData.id)
        ).filter(
            SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date),
            SignInData.ip_location_id == lab_id
        ).group_by('dow').order_by(func.count(SignInData.id).desc()).first()

        stats["busiest_day"] = calendar.day_name[busiest_day_query.dow - 1] if busiest_day_query else None

        # New vs Returning students calculation
        student_visits = db.session.query(
            SignInData.l_number,
            func.count(SignInData.id)
        ).filter(
            SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date),
            SignInData.ip_location_id == lab_id
        ).group_by(SignInData.l_number).all()

        new_students = len([visit for visit in student_visits if visit[1] == 1])
        returning_students = len(student_visits) - new_students

        stats["new_students"] = new_students
        stats["returning_students"] = returning_students

        # Most popular class calculation
        class_popularity_query = db.session.query(
            SignInData.class_selected,
            func.count(SignInData.id)
        ).filter(
            SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date),
            SignInData.ip_location_id == lab_id
        ).group_by(SignInData.class_selected).order_by(func.count(SignInData.id).desc()).first()

        stats["most_popular_class"] = class_popularity_query.class_selected if class_popularity_query else None

        # Hourly and Daily attendance calculations
        hourly_attendance = defaultdict(int)
        for record in sign_ins:
            hour = record.sign_in_timestamp.hour
            hourly_attendance[hour] += 1

        stats["hourly_attendance"] = [{"hour": hour, "attendance": round(count, 2)} for hour, count in hourly_attendance.items()]

        daily_attendance = defaultdict(int)
        for record in sign_ins:
            day_name = calendar.day_name[record.sign_in_timestamp.weekday()]
            daily_attendance[day_name] += 1

        stats["daily_attendance"] = [{"day": day, "attendance": round(count, 2)} for day, count in daily_attendance.items()]

    current_app.logger.debug(f"Stats: {stats}")

    # Return the final stats dictionary
    return stats


def send_welcome_email(l_number, lab_id):
    lab_location = IPLocation.query.get(lab_id)
    if not lab_location or not lab_location.welcome_email_enabled or not lab_location.email_template:
        return

    # Fetch student email
    student_email = get_student_email(l_number)
    if not student_email:
        logger.error(f"No email found for student with L number {l_number}")
        return

    # Construct the email
    subject = lab_location.email_template.subject
    body = lab_location.email_template.body

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = config['smtp']['SUPPORT_EMAIL']
    msg['To'] = student_email

    # Use msmtp to send the email
    with open('/tmp/email.txt', 'w') as file:
        file.write(msg.as_string())
    
    subprocess.run(["msmtp", "-a", config['smtp']['ACCOUNT'], student_email], input=msg.as_string(), text=True)


def get_student_email(l_number):
    """Retrieve the student's email address from the SSHFS file."""
    sshfs = create_sshfs()
    file_path = os.path.join(config['sshfs']['REMOTE_TSV_PATH'], config['sshfs']['LOCAL_STUDENT_FILE'])
    try:
        with sshfs.open(file_path, 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if row[0].strip() == l_number:
                    return row[5].strip()  # Assuming the email is in the 6th column
    except Exception as e:
        logger.error(f"Error reading SSHFS file: {e}")
    return None

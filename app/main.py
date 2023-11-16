from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
from flask_login import login_required, current_user
from flask_wtf.csrf import generate_csrf, validate_csrf
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timedelta, date, time
from email.mime.text import MIMEText
from app.models import db, SignInData, IPLocation, TermDates, LabMessage
from app.forms import LandingForm, LogoutForm, SignInForm, SignOutForm, LoginForm, CSRFProtectForm
from .config import load_config
from fs.sshfs import SSHFS
from fs import open_fs
from fs.errors import CreateFailed
from paramiko import util
from sqlalchemy import func, case, and_, or_


import subprocess
import os
import logging
import csv
import fs
import paramiko
import logging

main_bp = Blueprint('main', __name__)

config = load_config()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configure the logging level for Paramiko to DEBUG
util.log_to_file('paramiko.log', level=5)


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

    if lab_id and is_valid_lab_id(lab_id):
        lab_location = IPLocation.query.get(lab_id)
        messages = lab_location.lab_messages if lab_location else None
    else:
        lab_location = None
        messages = None

    message = get_latest_lab_message(lab_id) if lab_location else None

    # Calculate stats for every render_template call
    stats = get_student_stats(lab_id) if lab_id else None
    
    if form.validate_on_submit():
        # Obtain l_number directly from the form data
        l_number = form.l_number.data

        # Check for 'admin' input
        if l_number.lower() == "admin":
            return redirect(url_for('auth.login'))

        # Normalize l_number
        l_number = normalize_l_number(l_number)

        # Check if it's a valid student L number
        if not student_exists(l_number):
            flash('Invalid L number, please sign-in again.')
            return redirect(url_for('main.landing', lab_id=lab_id, stats=stats))

        # Proceed if valid student L number
        session['l_number'] = l_number

        action = choosesignout(l_number, lab_id)
        if action == 'sign_out':
            return redirect(url_for('main.sign_out', l_number=l_number))
        else:
            return redirect(url_for('main.sign_in', l_number=l_number))
        
    return render_template('landing.html', form=form, lab_location=lab_location, lab_location_name=lab_location_name, lab_id=lab_id, messages=messages, stats=stats)


def choosesignout(l_number, lab_id):
    # Check if student is already signed in today
    today = datetime.now().date()
    student_entries_today = SignInData.query.filter_by(l_number=l_number).all()

    student_today = None
    for entry in student_entries_today:
        if entry.sign_in_timestamp.date() == today and not entry.sign_out_timestamp:
            student_today = entry

    if student_today and not student_today.sign_out_timestamp:
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
    try:
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
    except Exception as e:
        current_app.logger.exception("SSHFS connection error")
        return None


@main_bp.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    try:
        form = SignInForm()

        current_app.logger.debug("sign_in function called")

        # Extract lab information
        lab_info = get_lab_info(request.remote_addr)
        lab_location_name = lab_info[0] if lab_info else 'Unknown Location'
        lab_id = lab_info[1] if lab_info else None

        # Fetch classes and set choices for class_selected
        classes_param = request.args.get('classes', '')
        classes = classes_param.split(',') if classes_param else get_student_classes(session.get('l_number', ''))
        classes.append('Other')
        form.class_selected.choices = [(cls, cls) for cls in classes]

        # Pre-select the first class if it exists
        if request.method == 'GET':
            if classes:
                form.class_selected.data = classes[0]

        # Prepopulate l_number from query string or session
        l_number = request.args.get('l_number') or session.get('l_number')
        if l_number:
            form.l_number.data = l_number
            form.l_number.render_kw = {'readonly': True}
        else:
            # Handle the case where l_number is not found
            flash('L number is missing. Please try again.', 'error')
            return redirect(url_for('main.landing'))

        print("Form data:", request.form)

        if form.validate_on_submit():
            current_app.logger.debug("Form is valid, processing sign-in")
            print("Class Selected:", form.class_selected.data)  # Debugging
            class_selected = form.class_selected.data

            sign_in_data = SignInData(
                l_number=l_number,
                lab_location=lab_location_name,
                class_selected=class_selected,
                sign_in_timestamp=datetime.now(),
                ip_location_id=lab_id
            )

            db.session.add(sign_in_data)
            db.session.commit()

            flash('Signed in successfully')
            current_app.logger.debug("Sign in processed successfully, redirecting...")
            return redirect(url_for('main.landing'))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error processing sign in: {e}")
        flash('An error occurred while signing in.', 'error')

    finally:
        # Moved the redirection into the exception handling to ensure it's always executed
        current_app.logger.debug("Rendering sign-in page or redirecting (finally block)")
        return render_template('sign_in.html', form=form, lab_location_name=lab_location_name) if not form.validate_on_submit() else redirect(url_for('main.landing'))


@main_bp.route('/sign-out', methods=['GET', 'POST'])
def sign_out():
    form = SignOutForm()
    l_number = request.args.get('l_number') or session.get('l_number')
    comment = form.comment.data
    continue_without_comment = request.args.get('continue')  # Check if continue was clicked

    # Ensure l_number is available
    if not l_number:
        flash('Error: L number missing.')
        return redirect(url_for('main.landing'))
    
    # Calculate daily time in lab
    daily_time = calculate_daily_time_in_lab(l_number)

    # Calculate total time in current term
    total_term_time = calculate_total_term_time(l_number)

    if continue_without_comment or form.validate_on_submit():
        # This will handle both clicking continue and submitting the form
        process_sign_out(l_number, form.comment.data if form.validate_on_submit() else "")
        flash('Signed out successfully.')
        session.pop('l_number', None)
        return redirect(url_for('main.landing'))
    
    return render_template('sign_out.html', form=form, l_number=l_number, daily_time=daily_time, total_term_time=total_term_time)


def process_sign_out(l_number, comment):
    sign_in_record = SignInData.query.filter_by(l_number=l_number, sign_out_timestamp=None).order_by(SignInData.sign_in_timestamp.desc()).first()
    try:
        send_comment_to_support(l_number, comment)
    except Exception as e:
        current_app.logger.error('Problem with sending comment to support')

    if sign_in_record:
        current_app.logger.info(f"Found sign-in record for L number {l_number}. Attempting sign-out...")
        sign_in_record.sign_out_timestamp = datetime.now()
        sign_in_record.comments = comment
        try:
            db.session.commit()
            session.pop('l_number', None)
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
    local_file_path = 'zsrsinf_cit.txt'
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


def get_lab_info(ip_address):
    """Retrieve lab location and ID based on the user's IP address."""
    ip_location = IPLocation.query.filter_by(ip_address=ip_address).first()
    if ip_location:
        return ip_location.location_name, ip_location.id
    return "Unknown Location", None


def get_lab_name(ip_address):
    """Retrieve lab location based on the user's IP address."""
    ip_location = IPLocation.query.filter_by(ip_address=ip_address).first()
    if ip_location:
        return ip_location.location_name
    return "Unknown Location"


def student_signed_in_today(l_number):
    """Check if the student is already signed in today."""
    return get_student_today(l_number) is not None


def process_sign_in(l_number, lab_location_name, class_selected, lab_id):
    """Process the student's sign-in."""
    sign_in_data = SignInData(
        l_number=l_number,
        lab_location=lab_location_name,
        class_selected=class_selected,
        sign_in_timestamp=datetime.now(),
        ip_location_id=lab_id
    )
    db.session.add(sign_in_data)
    db.session.commit()


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
    local_file_path = 'zsrslst_cit.txt'
    local_file_path_classes = 'zsrsecl_cit.txt'
    sshfs = create_sshfs()

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


@main_bp.route('/current_sign_ins/<lab_id>')
def current_sign_ins(lab_id):
    if lab_id != 'None' and lab_id.isdigit():
        lab_id = int(lab_id)
        print("Lab ID:", lab_id)  # Debug print statement

        sign_ins = SignInData.query.join(
            IPLocation, SignInData.ip_location_id == IPLocation.id
        ).filter(IPLocation.id == lab_id).all()

        # Print all records before filtering for sign_out_timestamp and date
        for sign_in in sign_ins:
            print(sign_in.l_number, sign_in.lab_location, sign_in.ip_location_id, sign_in.sign_in_timestamp, sign_in.sign_out_timestamp)

        count = len([sign_in for sign_in in sign_ins if sign_in.sign_out_timestamp is None and sign_in.sign_in_timestamp.date() == datetime.now().date()])
        
        print(f'Checking sign-ins for lab ID: {lab_id}')  # Verbose comment
        print(f'Number of users currently signed in: {count}')  # Verbose comment
        return jsonify(count=count)
    else:
        return jsonify({'error': 'Invalid lab ID'}), 404


def send_comment_to_support(l_number, comment):
    try:
        # Email details
        email = config['smtp']['SUPPORT_EMAIL']
        subject = "CIT Lab User Comment"
        body = f"Comment from L Number {l_number}:\n\n{comment}\n\nThank you,\n The Sign-in Form"

        # Create the email message
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = config['smtp']['SUPPORT_EMAIL']
        msg['To'] = email

        # Write the email to a file
        email_file_path = '/tmp/email.txt'  # Use a full path, e.g., in /tmp
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


@main_bp.route('/check-db')
def check_db():
    data = SignInData.query.all()
    output = "Database Records:<br>"
    for entry in data:
        output += f"L Number: {entry.l_number}, Lab: {entry.lab_location}, Class: {entry.class_selected}, Sign In: {entry.sign_in_timestamp}, Sign Out: {entry.sign_out_timestamp}<br>"
    return output


def get_current_term():
    # Assuming TermDates model has start_date and end_date to define a term
    current_date = datetime.now().date()
    current_term = TermDates.query.filter(TermDates.start_date <= current_date, TermDates.end_date >= current_date).first()
    return current_term


def default_sign_out(sign_in_timestamp):
    return datetime.combine(sign_in_timestamp.date(), time(16, 30))


def get_student_stats(lab_id):
    # Early return if no lab_id is provided
    if not lab_id:
        return None

    current_term = get_current_term()
    if not current_term:
        return None

    # Convert current_term.end_date to datetime at the end of the day (23:59:59)
    term_end_datetime = datetime.combine(current_term.end_date, time(23, 59, 59))

    sign_ins = SignInData.query.filter(
        SignInData.sign_in_timestamp.between(current_term.start_date, term_end_datetime),
        SignInData.ip_location_id == lab_id  # Filter by lab ID
    ).all()

    total_hours = round(
        sum(
            ((record.sign_out_timestamp or datetime.now()) - record.sign_in_timestamp).total_seconds() / 3600
            for record in sign_ins
        ), 2
    )

    # Calculate new and returning students count
    student_counts = db.session.query(
        SignInData.l_number,
        func.count(SignInData.l_number).label('visit_count')
    ).filter(
        SignInData.sign_in_timestamp.between(current_term.start_date, current_term.end_date),
        SignInData.ip_location_id == lab_id
    ).group_by(SignInData.l_number).all()

    single_visit_students_count = sum(1 for _, count in student_counts if count == 1)
    returning_students_count = sum(1 for _, count in student_counts if count > 1)

    ratio = returning_students_count / single_visit_students_count if single_visit_students_count else 0

    return {
        "total_hours": total_hours,
        "single_visit_students_count": single_visit_students_count,
        "returning_students_count": returning_students_count,
        "ratio": ratio
    }


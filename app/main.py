from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
from flask_login import login_required, current_user
from flask_wtf.csrf import generate_csrf, validate_csrf
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timedelta, date
from email.mime.text import MIMEText
from app.models import db, SignInData, IPLocation, TermDates, LabMessage
from app.forms import LandingForm, LogoutForm, SignInForm, SignOutForm, LoginForm, CSRFProtectForm
from .config import load_config
from fs.sshfs import SSHFS
from paramiko import util

import subprocess
import os
import logging
import csv

main_bp = Blueprint('main', __name__)

config = load_config()

# Configure the logging level for Paramiko to DEBUG
util.log_to_file('/tmp/paramiko.log', level=5)


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

    if form.validate_on_submit():
        l_number = normalize_l_number(form.l_number.data)
        session['l_number'] = l_number

        if not student_exists(l_number):
            flash('Invalid L number, please sign-in again.')
            return redirect(url_for('main.landing', lab_id=lab_id))

        # Additional logging to trace the flow
        print("Redirecting to chooseSignout")
        return chooseSignout(l_number, lab_id)

    # Additional logging for default return
    print("Rendering landing page template")
    return render_template('landing.html', form=form, lab_location=lab_location, lab_location_name=lab_location_name, lab_id=lab_id, messages=messages)

def chooseSignout(l_number, lab_id):
    try:
        # Check if student is already signed in today
        today = datetime.now().date()
        student_entries_today = SignInData.query.filter_by(l_number=l_number).all()

        student_today = None
        for entry in student_entries_today:
            if entry.sign_in_timestamp.date() == today and not entry.sign_out_timestamp:
                student_today = entry

        if student_today and not student_today.sign_out_timestamp:
            student_today.sign_out_timestamp = datetime.now()
            try:
                db.session.commit()
                current_app.logger.info('Student already signed in today. Signing them out.')
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f'Error signing out: {e}')
        
            return redirect(url_for('main.sign_out', l_number=l_number)) 

        else:
            return redirect(url_for('main.sign_in')) 


    except:
        db.session.rollback()
        current_app.logger.error(f'Error signing out: {e}')
        return handle_student_sign_in(l_number, lab_id)

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
        form.class_selected.choices = [(cls, cls) for cls in classes]

        # Prepopulate l_number from query string or session
        l_number = request.args.get('l_number') or session.get('l_number')
        if l_number:
            form.l_number.data = l_number
            form.l_number.render_kw = {'readonly': True}
        else:
            # Handle the case where l_number is not found
            flash('L number is missing. Please try again.', 'error')
            return redirect(url_for('main.landing'))

        if form.validate_on_submit():
            current_app.logger.debug("Form is valid, processing sign-in")
            
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
    l_number = form.l_number.data
    comment = form.comment.data

    if form.validate_on_submit():

        if process_sign_out(l_number, comment):
            flash('You have been signed out successfully.', 'success')
        else:
            flash('Error during sign out.', 'error')

        return redirect(url_for('main.landing'))
    else:
        return render_template('sign_out.html', form=form, comment=comment, l_number=l_number)


def process_sign_out(l_number, comment):
    sign_in_record = SignInData.query.filter_by(l_number=l_number, sign_out_timestamp=None).order_by(SignInData.sign_in_timestamp.desc()).first()
    
    send_comment_to_support(l_number, comment)

    if sign_in_record:
        sign_in_record.sign_out_timestamp = datetime.now()
        sign_in_record.comments = comment
        try:
            db.session.commit()
            session.pop('l_number', None)
            current_app.logger.info('User signed out')
            return True
        except Exception as e:
            db.session.rollback()
            return False
    return False


def student_exists(l_number):
    """Check if the student exists in the TSV file."""
    try:
        with SSHFS(
            host=config['sshfs']['HOST'],
            user=config['sshfs']['USER'],
            pkey=config['sshfs']['PRIVATE_KEY_PATH'],
            port=22
        ) as sshfs:
            tsv_file_path = config['sshfs']['REMOTE_TSV_PATH'] + '/zsrslst_cit.txt'
            if sshfs.exists(tsv_file_path):
                with sshfs.open(tsv_file_path, 'r') as file:
                    reader = csv.reader(file, delimiter='\t')
                    return any(l_number == row[0] for row in reader)
    except Exception as e:
        current_app.logger.error(f"SSHFS error: {e}")

    # Fallback to local file
    try:
        with open('zsrslst_cit.txt', 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            return any(l_number == row[0] for row in reader)
    except FileNotFoundError:
        current_app.logger.error('Local file zsrslst_cit.txt not found')
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

    try:
        with SSHFS(
            host=config['sshfs']['HOST'],
            user=config['sshfs']['USER'],
            pkey=config['sshfs']['PRIVATE_KEY_PATH']
        ) as sshfs:
            # Read from SSHFS if available
            if sshfs.exists('/data/zsrsinf_cit.txt'):
                with sshfs.open('/data/zsrsinf_cit.txt', 'r') as file:
                    reader = csv.reader(file, delimiter='\t')
                    for row in reader:
                        if l_number.strip('"') == row[0].strip('"'):
                            class_ids.append(row[1].strip('"'))

            if sshfs.exists('/data/zsrsecl_cit.txt'):
                with sshfs.open('/data/zsrsecl_cit.txt', 'r') as file:
                    reader = csv.reader(file, delimiter='\t')
                    for row in reader:
                        if row[1].strip('"') in class_ids:
                            class_name = f"{row[2]} {row[3]}: {row[4]}"
                            classes.append(class_name)
    except Exception as e:
        current_app.logger.error(f"SSHFS error: {e}")

        # Fallback to local files if SSHFS fails or is not available
        try:
            with open('zsrslst_cit.txt', 'r') as file:
                reader = csv.reader(file, delimiter='\t')
                for row in reader:
                    if l_number.strip('"') == row[0].strip('"'):
                        class_ids.append(row[1].strip('"'))

            with open('zsrsecl_cit.txt', 'r') as file:
                reader = csv.reader(file, delimiter='\t')
                for row in reader:
                    if row[1].strip('"') in class_ids:
                        class_name = f"{row[2]} {row[3]}: {row[4]}"
                        classes.append(class_name)

        except FileNotFoundError as e:
            current_app.logger.error(f"Local file not found: {e}")
            return []

    return list(set(classes))



@main_bp.route('/download_csv/<filename>')
def download_csv(filename):
    # Make sure the filename is safe to open
    if not os.path.basename(filename) == filename:
        abort(400, "Invalid filename")

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

from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
from flask_login import login_required, current_user
from flask_wtf.csrf import generate_csrf, validate_csrf
from itsdangerous import URLSafeTimedSerializer, BadSignature
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from io import StringIO
from app.models import db, SignInData, IPLocation
from app.forms import LandingForm, LogoutForm, SignInForm, SignOutForm, LoginForm, QuerySelectionForm, AddIPMappingForm, RemoveIPMappingForm, CSRFProtectForm
from .config import load_config

import csv
import subprocess
import os

main_bp = Blueprint('main', __name__)

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

    if form.validate_on_submit():
        l_number = form.l_number.data.upper()  # Convert to upper case to handle case-insensitivity
        # Prepend 'L' if it's not already there
        if not l_number.startswith('L'):
            l_number = f'L{l_number}'
        
        session['l_number'] = l_number  # Store the correctly formatted L number in the session

        if not student_exists(l_number):  # Use the student_exists function
            flash('Invalid L number, please sign-in again.')
            return redirect(url_for('main.landing'))

        sign_out_previous_day_students()  # Use the sign_out_previous_day_students function

        if student_signed_in_today(l_number):  # Use the student_signed_in_today function
            return handle_existing_sign_in(l_number)  # Use the handle_existing_sign_in function

        classes = get_student_classes(l_number)
        return redirect(url_for('main.sign_in', l_number=l_number, **{'classes[]': classes}))

    else:
        csrf_token = generate_csrf()
        form.csrf_token.data = csrf_token
        lab_id = session.get('lab_id', None)

        return render_template('landing.html', form=form, lab_id=lab_id)

@main_bp.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    form = SignInForm()
    l_number = session.get('l_number')
    if not l_number:
        return redirect_with_flash('Please start from the landing page.', 'error', 'main.landing')

    form.l_number.data = l_number
    form.l_number.render_kw = {'readonly': True}

    lab_location_name, lab_id = get_lab_info(request.remote_addr)

    form.class_selected.choices = [(cls, cls) for cls in get_student_classes(l_number)]
    
    if form.validate_on_submit():
        if form.l_number.data != l_number:
            return redirect_with_flash('Invalid L number submission.', 'error', 'main.landing')

        if student_signed_in_today(l_number):
            return handle_existing_sign_in(l_number)

        try:
            process_sign_in(l_number, lab_location_name, form.class_selected.data, lab_id)
            flash('Signed in successfully')
            return redirect(url_for('main.landing', lab_id=lab_id))
        except Exception as e:
            return handle_sign_in_error(e)

    return render_template('sign_in.html', form=form, lab_location_name=lab_location_name)

@main_bp.route('/sign-out', methods=['GET', 'POST'])
def checkout():
    form = SignOutForm()

    # Debug print to see the form data received
    print("Form received", form.data)

    if form.validate_on_submit():
        # Debug print to see if the form is validated
        print("Form validated")
        l_number = form.l_number.data
        comment = form.comment.data

        # Retrieve the latest sign-in record for the L number that hasn't signed out yet
        sign_in_record = SignInData.query.filter_by(
            l_number=l_number, sign_out_timestamp=None
        ).order_by(SignInData.sign_in_timestamp.desc()).first()

        if sign_in_record:
            # Set the sign-out timestamp to the current time
            sign_in_record.sign_out_timestamp = datetime.now()
            # Optionally, save the comment if you have a field for it
            sign_in_record.comments = comment
            try:
                db.session.commit()
                session.pop('l_number', None)

                flash('You have been signed out successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred while signing out: {e}', 'error')
                print(f'Error signing out: {e}')

        # After handling the sign-out, redirect to the landing page
        return redirect(url_for('main.landing'))
    else:
        # If the form didn't validate, show the sign-out page with the form again
        print("Form did not validate", form.errors)
        return render_template('sign_out.html', form=form)

    # If no L number is provided in the request args, redirect to the landing page
    l_number = request.args.get('l_number')
    if not l_number:
        flash('No L number provided for sign-out.', 'error')
        return redirect(url_for('main.landing'))

def student_exists(l_number):
    """Check if the student exists in the TSV file."""
    with open('students.tsv', 'r') as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            if l_number == row[0]:
                return True
    return False

def sign_out_previous_day_students():
    """Sign out students who signed in the previous day and haven't signed out yet."""
    yesterday = (datetime.now() - timedelta(days=1)).date()
    students_signed_in_yesterday = SignInData.query.filter(
        SignInData.sign_in_timestamp <= yesterday,
        SignInData.sign_out_timestamp.is_(None)
    ).all()
    for student in students_signed_in_yesterday:
        student.sign_out_timestamp = datetime.now()
    db.session.commit()

def get_student_today(l_number):
    """Get the most recent sign-in record for the student for today."""
    today = datetime.now().date()
    student_entries_today = SignInData.query.filter_by(l_number=l_number).all()
    return next((entry for entry in sorted(student_entries_today, key=lambda x: x.sign_in_timestamp, reverse=True)
                 if entry.sign_in_timestamp.date() == today and not entry.sign_out_timestamp), None)

def get_lab_info(ip_address):
    """Retrieve lab location and ID based on the user's IP address."""
    ip_location = IPLocation.query.filter_by(ip_address=ip_address).first()
    if ip_location:
        return ip_location.location_name, ip_location.id
    return "Unknown Location", None

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
    student_today.sign_out_timestamp = datetime.now()
    db.session.commit()
    flash('You are already signed in today. Signing out.')
    return redirect(url_for('main.checkout', l_number=l_number))

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
    """Retrieve the classes a student is enrolled in using the TSV files."""
    class_ids = []

    try:
        with open('studentsinclasses.tsv', 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if l_number == row[0]:  # Check if L number matches
                    class_ids.append(row[1])  # Add class ID
    except FileNotFoundError:
            # Handle the error, perhaps by sending a flash message or rendering a custom error page
            flash('Studentsinclasses file not found.', 'error')
            return redirect(url_for('main.landing'))  # Redirect to landing or an error page

    classes = []

    try:
        with open('classes.tsv', 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if row[1] in class_ids:  # Check if class ID matches
                    class_name = row[2] + " " + row[3] + ": " + row[4]
                    classes.append(class_name)
    except FileNotFoundError:
            # Handle the error, perhaps by sending a flash message or rendering a custom error page
            flash('Classes file not found.', 'error')
            return redirect(url_for('main.landing'))  # Redirect to landing or an error page

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
        return redirect(url_for('main.query_selection'))


@main_bp.route('/query_selection', methods=['GET', 'POST'])
@login_required
def query_selection():
    form = QuerySelectionForm()
    logout_form = LogoutForm()

    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data + timedelta(days=1)

        # Fetch data from DB
        data = SignInData.query.filter(
            SignInData.sign_in_timestamp >= start_date,
            SignInData.sign_in_timestamp < end_date
        ).all()
        # Generate a unique filename for the CSV
        csv_filename = f"attendance_data_{start_date}_{end_date}.csv"
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["L Number", "Lab Location", "Class Selected", "Sign-in Timestamp", "Sign-out Timestamp", "Comments"])
        for entry in data:
            writer.writerow([entry.l_number, entry.lab_location, entry.class_selected, entry.sign_in_timestamp,
                             entry.sign_out_timestamp, entry.comments])
        output.seek(0)

        # Save the CSV data in a temporary file on the server
        csv_path = os.path.join('/tmp', csv_filename)
        with open(csv_path, 'w') as f:
            f.write(output.getvalue())

        # Store the filename in the session for retrieval
        session['csv_filename'] = csv_filename

        # Add the filename to the template context
        return render_template('query_selection.html', form=form, logout_form=logout_form, data=data, csv_filename=csv_filename)
    
    else:
        if request.method == 'POST':
            flash('Form submission is invalid', 'error')

    # If it's a GET request or the POST request is processed, show the same query selection page without the download link
    return render_template('query_selection.html', form=form, logout_form=logout_form, csv_filename=None)

@main_bp.route('/current_sign_ins/<int:lab_id>')
def current_sign_ins(lab_id):
    sign_ins = SignInData.query.join(
        IPLocation, SignInData.ip_location_id == IPLocation.id
    ).filter(
        IPLocation.id == lab_id
    ).all()

    # Print all records before filtering for sign_out_timestamp and date
    for sign_in in sign_ins:
        print(sign_in.l_number, sign_in.lab_location, sign_in.ip_location_id, sign_in.sign_in_timestamp, sign_in.sign_out_timestamp)

    count = len([sign_in for sign_in in sign_ins if sign_in.sign_out_timestamp is None and sign_in.sign_in_timestamp.date() == datetime.now().date()])
    
    print(f'Checking sign-ins for lab ID: {lab_id}')  # Verbose comment
    print(f'Number of users currently signed in: {count}')  # Verbose comment
    return jsonify(count=count)


@main_bp.route('/ip-management', methods=['GET', 'POST'])
@login_required
def ip_management():
    add_ip_form = AddIPMappingForm()
    remove_ip_form = RemoveIPMappingForm()
    logout_form = LogoutForm()

    # Inspect the attributes of the submit field
    print("Submit field attributes:")
    print("Label:", add_ip_form.submit.label.text)
    print("Name:", add_ip_form.submit.name)
    print("Data:", add_ip_form.submit.data)
    
    # Inspect the attributes of the remove submit field
    print("Remove submit field attributes:")
    print("Label:", remove_ip_form.remove_submit.label.text)
    print("Name:", remove_ip_form.remove_submit.name)
    print("Data:", remove_ip_form.remove_submit.data)
    print("Form data:", request.form)  # Add this to log form data

    if request.method == 'POST':
        if add_ip_form.validate_on_submit():
            current_app.logger.info('Attempting to add IP mapping.')
            # Logic to add an IP mapping
            new_ip_location = IPLocation(
                ip_address=add_ip_form.ip_address.data,
                location_name=add_ip_form.location_name.data
            )
            db.session.add(new_ip_location)
            try:
                db.session.commit()
                flash('IP mapping added successfully.', 'success')
                current_app.logger.info('IP mapping added successfully.')

            except Exception as e:
                db.session.rollback()
                flash(f'Error adding IP mapping: {e}', 'error')
                current_app.logger.warning('Add IP Form did not validate.')

        elif remove_ip_form.validate_on_submit():
            current_app.logger.info('Attempting to remove IP mapping.')
            # Logic to remove an IP mapping
            location_to_remove = remove_ip_form.remove_location_name.data
            ip_location = IPLocation.query.filter_by(location_name=location_to_remove).first()
            if ip_location:
                db.session.delete(ip_location)
                try:
                    db.session.commit()
                    flash('IP mapping removed successfully.', 'success')
                    current_app.logger.info('IP mapping removed successfully.')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error removing IP mapping: {e}', 'error')
            else:
                flash('Location name not found.', 'error')

    return render_template('ip_management.html', add_ip_form=add_ip_form, remove_ip_form=remove_ip_form, logout_form=logout_form)

@main_bp.route('/set-message', methods=['GET', 'POST'])
@login_required
def set_message():
    if not current_user.can_set_message:
        flash('You do not have permission to set a message.', 'error')
        return redirect(url_for('main.landing'))

    form = MessageForm()
    if form.validate_on_submit():
        # Logic to set the message for the lab
        flash('Your message has been set.', 'success')
        return redirect(url_for('main.landing'))

    return render_template('set_message.html', form=form)

def send_comment_to_support(l_number, comment):
    # Load configuration
    config = load_config()
    print(config)  # Add this line to debug the config loading
    config.update(config)

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


@main_bp.route('/check-db')
def check_db():
    data = SignInData.query.all()
    output = "Database Records:<br>"
    for entry in data:
        output += f"L Number: {entry.l_number}, Lab: {entry.lab_location}, Class: {entry.class_selected}, Sign In: {entry.sign_in_timestamp}, Sign Out: {entry.sign_out_timestamp}<br>"
    return output

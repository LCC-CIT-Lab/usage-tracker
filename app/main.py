from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_from_directory
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
        l_number = form.l_number.data
        valid_l_number = False

        # Prepend 'L' if it's not already there
        if not l_number.upper().startswith('L'):
            l_number = f'L{l_number}'
            
        try:
            with open('students.tsv', 'r') as file:
                reader = csv.reader(file, delimiter='\t')
                for row in reader:
                    if l_number == row[0]:
                        valid_l_number = True
                        break
        except FileNotFoundError:
                # Handle the error, perhaps by sending a flash message or rendering a custom error page
                flash('Student file not found.', 'error')
                return redirect(url_for('main.landing'))  # Redirect to landing or an error page

        if not valid_l_number:
            flash('Invalid L number, please sign-in again.')
            return redirect(url_for('main.landing'))

        yesterday = (datetime.now() - timedelta(days=1)).date()
        students_signed_in_yesterday = SignInData.query.filter(SignInData.sign_in_timestamp <= yesterday,
                                                               SignInData.sign_out_timestamp.is_(None)).all()
        for student in students_signed_in_yesterday:
            student.sign_out_timestamp = datetime.now()
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

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
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                raise e
            current_app.logger.info('Student already signed in today. Signing them out.')
            return redirect(url_for('main.checkout', l_number=l_number))

        classes = get_student_classes(l_number)
        return redirect(url_for('main.sign_in', l_number=l_number, **{'classes[]': classes}))
    else:
        # Pass the generated CSRF token to the template
        csrf_token = generate_csrf()
        form.csrf_token.data = csrf_token

        return render_template('landing.html', form=form)


@main_bp.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    form = SignInForm()
    
    # Get the user's IP address
    user_ip = request.remote_addr
    # Look up the lab location based on the IP address
    ip_location = IPLocation.query.filter_by(ip_address=user_ip).first()
    lab_location_name = ip_location.location_name if ip_location else "Unknown Location"

    # Get l_number and available_classes from the request or set defaults
    l_number = request.args.get('l_number', '')
    available_classes = request.args.getlist('classes[]') or []

    # On GET request, store the available classes in the session
    if request.method == 'GET':
        available_classes = request.args.getlist('classes[]') or []
        session['available_classes'] = available_classes
        current_app.logger.debug(f"GET - Available classes: {available_classes}")

    else:
        # On POST request, retrieve the available classes from the session
        available_classes = session.get('available_classes', [])
        current_app.logger.debug(f"POST - Available classes from session: {available_classes}")

    # Set the form choices from the available classes
    form.class_selected.choices = [(cls, cls) for cls in available_classes]
    current_app.logger.debug(f"Form choices before validation: {form.class_selected.choices}")

    # Pre-populate form fields if l_number is provided in the query string
    if l_number:
        form.l_number.data = l_number
        form.l_number.render_kw = {'readonly': True}

    # Debug: Print available classes
    print("Available classes:", available_classes)

    # Debug: Print form choices before validation
    print("Form choices before validation:", form.class_selected.choices)

    # IMPORTANT: Set the choices for the POST request BEFORE form validation
    if request.method == 'POST':
        # You must retrieve and set the choices again from the database or session
        # because the form doesn't maintain state between requests
        form.class_selected.choices = [(cls, cls) for cls in available_classes]

        # Debug: Print form choices on POST request before validation
        print("Form choices on POST request before validation:", form.class_selected.choices)

    # Process the valid form submission
    if form.validate_on_submit():
        l_number = form.l_number.data
        class_selected = form.class_selected.data

        # Check if student is already signed in today
        today = datetime.now().date()
        student_entries_today = SignInData.query.filter_by(l_number=l_number).all()

        student_today = None
        for entry in student_entries_today:
            if entry.sign_in_timestamp.date() == today and not entry.sign_out_timestamp:
                student_today = entry
                break

        if student_today and not student_today.sign_out_timestamp:
            student_today.sign_out_timestamp = datetime.now()
            try:
                db.session.commit()
                current_app.logger.info('Student already signed in today. Signing them out.')
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f'Error signing out: {e}')
            return redirect(url_for('main.landing'))

        sign_in_data = SignInData(
            l_number=l_number,
            lab_location=lab_location_name,  # Use the lab location name determined by IP
            class_selected=class_selected,
            sign_in_timestamp=datetime.now()
        )

        db.session.add(sign_in_data)
        try:
            db.session.commit()
            current_app.logger.info('Signed in successfully')
            return redirect(url_for('main.landing'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f'Error signing in: {e}')
            flash('An error occurred while signing in.', 'error')

    # If it's a GET request or if the form didn't validate, return the sign-in page
    # Debug: Print form errors if there are any
    if form.errors:
        print("Form errors:", form.errors)
 
    return render_template('sign_in.html', form=form, lab_location_name=lab_location_name)

@main_bp.route('/sign-out', methods=['GET', 'POST'])
def checkout():
    form = SignOutForm()
    print("Form received", form.data)  # Debug print to see the form data received

    if form.validate_on_submit():
        print("Form validated")  # Debug print to see if the form is validated
        comment = form.comment.data
        l_number = form.l_number.data

        send_comment_to_support(l_number, comment)

        return redirect(url_for('main.landing'))

    print("Form did not validate", form.errors)  # Debug print to see form errors
    l_number = request.args.get('l_number')
    if not l_number:
        return redirect(url_for('main.landing'))
    return render_template('sign_out.html', form=form)



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
                current_app.logger.info('IP mapping removed successfully.')

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

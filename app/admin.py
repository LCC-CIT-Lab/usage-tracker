from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, session, send_file, Response
from flask_login import login_required, current_user
from app.utils import get_lab_info
from app.models import db, User, IPLocation, TermDates, LabMessage, SignInData, EmailTemplate, ManualSignInSettings
from app.forms import LoginForm, AddUserForm, MessageForm, QuerySelectionForm, AddIPMappingForm, RemoveIPMappingForm, UploadCSVForm, TermDatesForm, ManageEmailsForm, ToggleManualSignInForm, QRCodeForm, FeedbackForm
from functools import wraps
from datetime import datetime, timedelta, time
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from io import StringIO, BytesIO
from email.mime.text import MIMEText

import traceback
import csv
import os
import qrcode
import base64
import shutil
import subprocess



admin_bp = Blueprint('admin', __name__)


ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Decorator to require admin access
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied: You do not have the necessary permissions.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


# Function to sign out students
def sign_out_previous_day_students():
    yesterday = (datetime.now() - timedelta(days=1)).date()
    sign_out_time = datetime.combine(yesterday, datetime.strptime('16:30', '%H:%M').time())

    students_signed_in_yesterday = SignInData.query.filter(
        db.func.date(SignInData.sign_in_timestamp) == yesterday,
        SignInData.sign_out_timestamp.is_(None)
    ).all()

    for student in students_signed_in_yesterday:
        student.sign_out_timestamp = sign_out_time
        db.session.commit()

    current_app.logger.info(f'Signed out {len(students_signed_in_yesterday)} students from the previous day.')


# Function to sign out the days students
def sign_out_task():
    from app import create_app
    app = create_app()  # Create an instance of the app
    with app.app_context():
        sign_out_previous_day_students()

# Function to create an admin to start off
def create_admin(app):
    with app.app_context():
        # Load the configuration
        config = current_app.config

        default_admin_password = config['encryption']['DEFAULT_ADMIN_PASSWORD']
        default_admin_username = config['encryption']['DEFAULT_ADMIN_USERNAME']
        default_admin_email = config['encryption']['DEFAULT_ADMIN_EMAIL']

        # Check if admin user already exists
        existing_admin = User.query.filter_by(username=default_admin_username).first()
        if not existing_admin:
            # Create an admin user with default credentials
            admin_user = User(
                username=default_admin_username, 
                email=default_admin_email
            )
            admin_user.set_password(default_admin_password)
            admin_user.is_admin = True  # Set as admin
            # ... set other fields if necessary

            db.session.add(admin_user)
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error creating admin user: {e}")


# Function to sign in to the admin dashboard
@admin_bp.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    lab_info = get_lab_info(request.remote_addr)
    lab_location_name, lab_location_id = lab_info  # Unpack the tuple
    session.pop('csv_filename', None)

    if current_user.is_authenticated:
        # Pass the is_admin variable and the IPLocation instance to the template
        return render_template('admin_dashboard.html', is_admin=current_user.is_admin,
                               lab_location_id=lab_location_id)
    else:
        flash('Please log in with an admin account to access this page.', 'error')
        return redirect(url_for('auth.login'))


# Query Selection #
###################
@admin_bp.route('/query_selection', methods=['GET', 'POST'])
@login_required
def query_selection():
    form = QuerySelectionForm()
    term_dates = TermDates.query.all()

    # Populate form choices
    form.term_date_range.choices = [(0, 'Select Term Date Range')] + [
        (td.id, f"{td.term_name}: {td.start_date.strftime('%Y-%m-%d')} to {td.end_date.strftime('%Y-%m-%d')}")
        for td in term_dates
    ]
    form.location_name.choices = [('0', 'All Assigned Locations')] + \
                                 [(str(loc.id), loc.location_name) for loc in current_user.ip_locations]

    if form.validate_on_submit():
        selected_location = form.location_name.data
        start_date, end_date = get_date_range(form, term_dates)

        location_ids = [loc.id for loc in current_user.ip_locations] if selected_location == '0' else [int(selected_location)]
        data = SignInData.query.filter(
            SignInData.sign_in_timestamp.between(start_date, end_date),
            SignInData.ip_location_id.in_(location_ids)
        ).all()

        if data:
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(["L Number", "Lab Location", "Class Selected", "Sign-in Timestamp", "Sign-out Timestamp", "Sign-in Comments", "Sign-out Comments"])

            for entry in data:
                sign_out_timestamp = entry.sign_out_timestamp if entry.sign_out_timestamp else default_sign_out(entry.sign_in_timestamp)
                writer.writerow([entry.l_number, entry.lab_location, entry.class_selected, entry.sign_in_timestamp, sign_out_timestamp, entry.sign_in_comments, entry.comments])

            session['csv_data'] = output.getvalue()
            output.close()
            flash('Report generated successfully.', 'success')
        else:
            flash('No data found for the selected criteria.', 'info')

    return render_template('query_selection.html', form=form, user_lab_locations=current_user.ip_locations, term_dates=term_dates)


def default_sign_out(sign_in_timestamp):
    return datetime.combine(sign_in_timestamp.date(), time(16, 30))


def get_date_range(form, term_dates):
    if form.term_date_range.data and form.term_date_range.data != '0':
        term_date = next((td for td in term_dates if str(td.id) == form.term_date_range.data), None)
        if term_date:
            return term_date.start_date, term_date.end_date + timedelta(days=1)
    return form.start_date.data, form.end_date.data


def get_date_range(form, term_dates):
    """Get the date range from the form selection or term dates."""
    if form.term_date_range.data and form.term_date_range.data != '0':
        # Find the term date from the list based on the selected ID
        term_date = next((td for td in term_dates if str(td.id) == form.term_date_range.data), None)
        if term_date:
            return term_date.start_date, term_date.end_date + timedelta(days=1)
    return form.start_date.data, form.end_date.data
    

@admin_bp.route('/stream_csv')
@login_required
def stream_csv():
    csv_data = session.get('csv_data')
    if not csv_data:
        flash('No CSV data found. Please generate the report again.', 'error')
        return redirect(url_for('admin.query_selection'))

    def generate():
        yield csv_data
    return Response(generate(), mimetype='text/csv', headers={"Content-disposition": "attachment; filename=attendance_data.csv"})


# ADMIN USER MANAGEMENT #
#########################
@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
@require_admin
def user_management():
    
    # Clear the session variable when the page loads
    session.pop('last_selected_user_id', None)

    if request.method == 'POST':
        selected_user_id = request.form.get('selected_user')
        session['last_selected_user_id'] = selected_user_id
    else:
        selected_user_id = session.get('last_selected_user_id')

    form = LoginForm()
    add_user_form = AddUserForm()
    users = User.query.all()
    current_app.logger.debug('Users List: %s', users)

    ip_locations = IPLocation.query.all()


    return render_template('user_management.html', users=users, selected_user_id=selected_user_id, add_user_form=add_user_form, form=form,
                           ip_locations=ip_locations)


# Function to retrieve all admin from the database
def get_all_users():
    return User.query.all()


# Function to add a admin to the database
@admin_bp.route('/add_user', methods=['POST'])
@login_required
@require_admin
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = 'is_admin' in request.form

    if not (username and email and password):
        flash('Please enter all the required fields.', 'error')
        return redirect(url_for('admin.user_management'))

    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        flash('A user with this email or username already exists.', 'error')
    else:
        # Creating a new user
        new_user = User()
        new_user.username = username
        new_user.email = email
        new_user.password = new_user.set_password(password)
        new_user.is_admin = is_admin  # Set additional attributes

        try:
            # Add the new user to the session and commit
            db.session.add(new_user)
            db.session.commit()
            flash('New user added successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            traceback_str = traceback.format_exc()  # This will give you the full traceback as a string.
            current_app.logger.error(traceback_str)  # This will log the full traceback.
            flash(f'An error occurred while creating the user: {e}', 'error')

    return redirect(url_for('admin.user_management'))


@admin_bp.route('/remove_user/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def remove_user(user_id, redirect_enabled=True):
    try:
        user = get_user_by_id(user_id)
        current_app.logger.info(f"Attempting to remove user with ID: {user_id}")

        LabMessage.query.filter_by(user_id=user.id).delete()

        db.session.delete(user)
        db.session.commit()
        flash('User removed successfully.', 'success')
        current_app.logger.info(f"User with ID {user_id} removed successfully.")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error removing user with ID {user_id}: {e}", exc_info=True)
        flash(f'Error removing user: {e}', 'error')

    if redirect_enabled:
        return redirect(url_for('admin.user_management'))

    return redirect(url_for('admin.user_management'))


@admin_bp.route('/apply_user_actions', methods=['POST'])
@login_required
@require_admin
def apply_user_actions():
    selected_user_id = request.form.get('selected_user')
    action = request.form.get('action')

    if not selected_user_id:
        flash('No user selected.', 'error')
        return redirect(url_for('admin.user_management'))

    # Store the last selected user ID in session
    session['last_selected_user_id'] = selected_user_id

    user = User.query.get(selected_user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.user_management'))

    if action == 'delete_user':
        delete_user(user)
    else:
        flash('Invalid action.', 'error')

    return redirect(url_for('admin.user_management'))


def delete_user(user):
    try:
        LabMessage.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User removed successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error removing user: {e}', 'error')


# TERM DATES MANAGEMENT #
#########################

@admin_bp.route('/term_dates_management', methods=['GET', 'POST'])
@login_required
@require_admin
def term_dates_management():
    form = TermDatesForm()
    upload_csv_form = UploadCSVForm()  # Instantiate the form for CSV upload
    term_dates = TermDates.query.all()

    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        term_name = determine_term_name(start_date)  # Use the function to determine the term name

        new_term_dates = TermDates(
            term_name=term_name,
            start_date=start_date,
            end_date=end_date
        )
        db.session.add(new_term_dates)
        try:
            db.session.commit()
            flash('Term dates added successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'error')

    term_dates = TermDates.query.all()
    return render_template('term_dates_management.html', form=form, upload_csv_form=upload_csv_form, term_dates=term_dates)


def determine_term_name(start_date):
    month = start_date.month
    year = start_date.year
    term_name = f'Unknown Term {year}'  # Default term name

    if month == 1:  # January
        term_name = f'Winter {year}'
    elif month == 3:  # March
        term_name = f'Spring {year}'
    elif month == 5:  # June
        term_name = f'Summer {year}'
    elif month == 9:  # June
        term_name = f'Fall {year}'
    return term_name


@admin_bp.route('/delete_term_date', methods=['POST'])
@login_required
@require_admin
def delete_term_date():
    term_date_id = request.form.get('term_date_id')
    if not term_date_id:
        flash('No term date selected.', 'error')
        return redirect(url_for('admin.term_dates_management'))

    term_date = TermDates.query.get(term_date_id)
    if not term_date:
        flash('Term date not found.', 'error')
    else:
        try:
            db.session.delete(term_date)
            db.session.commit()
            flash('Term date deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'error')

    return redirect(url_for('admin.term_dates_management'))


@admin_bp.route('/upload_term_dates_csv', methods=['GET', 'POST'])
@login_required
@require_admin
def upload_term_dates_csv():
    file = request.files['csv_file']
    # Define the path for the uploads directory
    uploads_folder = os.path.join(current_app.root_path, 'uploads')

    # Check if the directory exists, create it if it doesn't
    if not os.path.exists(uploads_folder):
        os.makedirs(uploads_folder)

    # Define the full path including the file name
    csv_path = os.path.join(uploads_folder, secure_filename(file.filename))

    # Save the file
    file.save(csv_path)

    try:
        with open(csv_path, mode='r') as csv_file:
            csv_data = csv.reader(csv_file)
            next(csv_data, None)  # Skip header
            for row in csv_data:
                start_date = datetime.strptime(row[0], '%m/%d/%y').date()
                end_date = datetime.strptime(row[1], '%m/%d/%y').date()
                term_name = determine_term_name(start_date)

                new_term_dates = TermDates(term_name=term_name, start_date=start_date, end_date=end_date)
                db.session.add(new_term_dates)
            db.session.commit()
        flash('Term dates added successfully from CSV.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing CSV file: {e}', 'error')
    finally:
        os.remove(csv_path)  # Clean up the uploaded file

    return redirect(url_for('admin.term_dates_management'))


# SET MESSAGE MANAGEMENT #
##########################
@admin_bp.route('/set_message', methods=['GET', 'POST'])
@login_required
def set_message():
    if not current_user.ip_locations:
        flash('You do not have permission to set messages.', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    form = MessageForm()

    # Fetch locations based on user's permissions
    if current_user.is_admin:
        form.lab_location_id.choices = [(loc.id, loc.location_name) for loc in IPLocation.query.all()]
    else:
        form.lab_location_id.choices = [(loc.id, loc.location_name) for loc in current_user.ip_locations]

    if form.validate_on_submit():
        message = LabMessage(
            content=form.content.data,
            lab_location_id=form.lab_location_id.data,
            user_id=current_user.id
        )
        db.session.add(message)
        db.session.commit()
        flash('Your message has been posted.', 'success')
        return redirect(url_for('admin.set_message'))

    # Only show messages for the locations assigned to the user
    lab_locations = current_user.ip_locations if not current_user.is_admin else IPLocation.query.all()

    return render_template('set_message.html', form=form, lab_locations=lab_locations)


@admin_bp.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    # Query for the message to delete
    message = LabMessage.query.get_or_404(message_id)
    # Ensure the current user has permission to delete the message
    if message.user_id == current_user.id:
        db.session.delete(message)
        db.session.commit()
        flash('Message deleted successfully.', 'success')
    else:
        flash('You do not have permission to delete this message.', 'error')
    return redirect(url_for('admin.set_message', lab_location_id=message.lab_location_id))


## IP MAPPING MANAGEMENT ##
##########################
@admin_bp.route('/ip_management', methods=['GET', 'POST'])
@login_required
def ip_management():
    add_ip_form = AddIPMappingForm()
    remove_ip_form = RemoveIPMappingForm()
    user_ip = request.remote_addr


    # For admin users, show all IP mappings. For non-admin, show only their mappings.
    if current_user.is_admin:
        ip_locations = IPLocation.query.all()
    else:
        ip_locations = current_user.ip_locations

    if request.method == 'POST':
        # Non-admin users can only add or remove their own mappings
        if not current_user.is_admin:
            if add_ip_form.validate_on_submit():
                new_ip_location = IPLocation(ip_address=add_ip_form.ip_address.data, location_name=add_ip_form.location_name.data)
                db.session.add(new_ip_location)
                db.session.flush()  # This ensures the new object has an ID assigned
                current_user.ip_locations.append(new_ip_location)
                db.session.commit()
                flash('IP mapping added successfully.', 'success')
            elif remove_ip_form.validate_on_submit():
                ip_id_to_remove = int(remove_ip_form.remove_ip_id.data)
                ip_location_to_remove = IPLocation.query.get(ip_id_to_remove)
                if ip_location_to_remove in current_user.ip_locations:
                    db.session.delete(ip_location_to_remove)
                    db.session.commit()
                    flash('IP mapping removed successfully.', 'success')

        # Admin users can add or remove any mappings
        elif current_user.is_admin:
            if add_ip_form.validate_on_submit():
                new_ip_location = IPLocation(ip_address=add_ip_form.ip_address.data, location_name=add_ip_form.location_name.data)
                db.session.add(new_ip_location)
                db.session.commit()
                flash('IP mapping added successfully.', 'success')
            elif remove_ip_form.validate_on_submit():
                ip_location_to_remove = IPLocation.query.get(remove_ip_form.remove_ip_id.data)
                db.session.delete(ip_location_to_remove)
                db.session.commit()
                flash('IP mapping removed successfully.', 'success')

    return render_template('ip_management.html', add_ip_form=add_ip_form, remove_ip_form=remove_ip_form, ip_mappings=ip_locations, user_ip=user_ip)


@admin_bp.route('/admin/update_user_mappings', methods=['POST'])
@login_required
@require_admin
def update_user_mappings():
    selected_user_id = request.form.get('selected_user_id')
    user = get_user_by_id(selected_user_id)

    # Update user's IP mappings
    selected_ip_mappings_ids = request.form.getlist('selected_ip_mappings')
    user.ip_locations.clear()
    for ip_id in selected_ip_mappings_ids:
        ip_location = IPLocation.query.get(ip_id)
        if ip_location:
            user.ip_locations.append(ip_location)

    db.session.commit()
    flash('User settings updated successfully.', 'success')
    return redirect(url_for('admin.user_management'))




@admin_bp.route('/remove_user_ip_mapping/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def remove_user_ip_mapping(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
    else:
        db.session.commit()
        flash('User IP mapping removed successfully.', 'success')

    return redirect(url_for('admin.user_management'))


# Function to add an IP mapping location to the database
def add_ip_mapping(ip_mapping_form):
    new_ip_mapping = IPLocation(
        ip=ip_mapping_form.ip.data,
        location_name=ip_mapping_form.location_name.data
    )
    db.session.add(new_ip_mapping)
    db.session.commit()


# Function to remove an IP mapping location from the database
@admin_bp.route('/remove_ip_mapping', methods=['POST'])
@login_required
@require_admin
def remove_ip_mapping():
    ip_locations = IPLocation.query.all()
    remove_ip_form = RemoveIPMappingForm()
    remove_ip_form.remove_ip_id.choices = [(ip.id, f"{ip.ip_address} - {ip.location_name}") for ip in ip_locations]

    if remove_ip_form.validate_on_submit():
        ip_location = IPLocation.query.get(remove_ip_form.remove_ip_id.data)
        if ip_location:
            db.session.delete(ip_location)
            db.session.commit()
            flash('IP mapping removed successfully.', 'success')
        else:
            flash('IP mapping not found.', 'error')
    else:
        flash('Form validation error.', 'error')

    return redirect(url_for('admin.ip_management'))


@admin_bp.route('/get_user_ip_mappings/<int:user_id>')
@login_required
@require_admin
def get_user_ip_mappings(user_id):
    user = get_user_by_id(user_id)
    assigned_ips = [ip_location.id for ip_location in user.ip_locations]

    # Add the user's message and email permission states to the response
    user_details = {
        'assignedIps': assigned_ips,
    }
    return jsonify(user_details)


# Welcome Email Management #
############################
@admin_bp.route('/manage_emails', methods=['GET', 'POST'])
@login_required
def manage_emails():
    lab_id = request.args.get('lab_id', type=int)
    form = ManageEmailsForm()

    # Fetch only lab locations assigned to the user
    user_lab_locations = current_user.ip_locations if not current_user.is_admin else IPLocation.query.all()

    if not lab_id and user_lab_locations:
        lab_id = user_lab_locations[0].id  # Default to the first location

    lab_location = IPLocation.query.get_or_404(lab_id)

    # Check if email_template exists, if not, create a new one
    if not lab_location.email_template:
        lab_location.email_template = EmailTemplate(
            subject="Default Subject",
            body="Default Body",
            lab_location_id=lab_id
        )
        db.session.add(lab_location.email_template)
        db.session.commit()

    if form.validate_on_submit():
        # Update the lab_location with form data
        lab_location.email_template.subject = form.subject.data
        lab_location.email_template.body = form.body.data
        lab_location.welcome_email_enabled = 'enable_email' in request.form
        lab_location.custom_email = form.custom_email.data or current_app.config['smtp']['SUPPORT_EMAIL']

        db.session.commit()
        flash('Email settings updated successfully.', 'success')
        return redirect(url_for('admin.manage_emails', lab_id=lab_id))

    # Populate the form with existing data
    form.subject.data = lab_location.email_template.subject
    form.body.data = lab_location.email_template.body
    form.custom_email.data = lab_location.custom_email

    return render_template('manage_emails.html', form=form,
                           lab_location=lab_location, lab_id=lab_id, 
                           enable_email=lab_location.welcome_email_enabled,
                           user_lab_locations=user_lab_locations)



@admin_bp.route('/admin/generate_qr_code', methods=['GET', 'POST'])
@login_required
def generate_qr_code():
    form = QRCodeForm()  # Assuming you have a form for location selection

    # Fetch only lab locations assigned to the user
    form.location_id.choices = [(loc.id, loc.location_name) for loc in current_user.ip_locations]

    qr_image_base64 = None

    if form.validate_on_submit():
        # Generate QR Code based on the selected location
        selected_location_id = form.location_id.data
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url_for('main.landing', lab_id=selected_location_id, _external=True))
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered)
        qr_image_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template('generate_qr_code.html', form=form, qr_image_base64=qr_image_base64)

@admin_bp.route('/toggle_manual_signin', methods=['GET', 'POST'])
@login_required
def toggle_manual_signin():
    form = ToggleManualSignInForm()

    # Populate location choices for current user
    user_ip_locations = current_user.ip_locations if not current_user.is_admin else IPLocation.query.all()
    form.location_id.choices = [(loc.id, loc.location_name) for loc in user_ip_locations]

    if form.validate_on_submit():
        manual_signin_enabled = form.manual_signin_enabled.data
        selected_location_id = form.location_id.data

        # CSV file processing
        csv_file = request.files.get('csv_file')
        l_numbers = parse_csv_to_list(csv_file.read().decode('utf-8')) if csv_file and allowed_file(csv_file.filename) else []

        # Class options and sign-out comment email
        class_options = form.manual_class_options.data.split(',') if form.manual_class_options.data else []

        # Store settings in database or session
        store_manual_signin_settings(selected_location_id, manual_signin_enabled, l_numbers, class_options)

        flash('Manual sign-in settings updated.', 'success')
        return redirect(url_for('admin.toggle_manual_signin'))

    # GET request handling
    # Load existing settings if any
    load_existing_settings(form)

    return render_template('toggle_manual_signin.html', form=form)


def store_manual_signin_settings(location_id, enabled, l_numbers, class_options):
    # Convert L-numbers list to CSV string
    l_numbers_csv = ','.join(l_numbers)

    # Fetch existing settings for the location or create a new one
    settings = ManualSignInSettings.query.filter_by(location_id=location_id).first()
    if settings:
        # Update existing settings
        settings.manual_signin_enabled = enabled
        settings.l_numbers_csv = l_numbers_csv
        settings.class_options = ','.join(class_options)
        current_app.logger.info('Updated manual sign-in settings for location {}'.format(location_id))
    else:
        # Create new settings
        settings = ManualSignInSettings(
            location_id=location_id,
            manual_signin_enabled=enabled,
            l_numbers_csv=l_numbers_csv,
            class_options=','.join(class_options),
        )
        db.session.add(settings)
        current_app.logger.info('Created new manual sign-in settings for location {}'.format(location_id))

    try:
        db.session.commit()
        current_app.logger.info('Manual sign-in settings stored successfully.')
    except Exception as e:
        current_app.logger.error('Error storing manual sign-in settings: {}'.format(e))
        db.session.rollback()


def load_existing_settings(form):
    # Assuming the user can only edit settings for their locations
    user_locations = [loc.id for loc in current_user.ip_locations]
    settings = ManualSignInSettings.query.filter(ManualSignInSettings.location_id.in_(user_locations)).first()

    if settings:
        form.manual_signin_enabled.data = settings.manual_signin_enabled
        form.location_id.data = settings.location_id
        form.manual_class_options.data = settings.class_options
    else:
        # Default values if no settings are found
        form.manual_signin_enabled.data = False
        form.location_id.data = user_locations[0] if user_locations else None
        form.manual_class_options.data = ''


def parse_csv_to_list(csv_content):
    reader = csv.reader(StringIO(csv_content))
    return [row[0] for row in reader if row]  # Extract the first column


@admin_bp.route('/export_db')
@login_required
@require_admin
def export_db():
    db_path = os.path.join(current_app.root_path, 'attendance.db')  # Adjust the path
    temp_backup_path = os.path.join(current_app.root_path, 'temp', 'temp_db_backup.sqlite')

    if not os.path.exists(os.path.join(current_app.root_path, 'temp')):
        os.makedirs(os.path.join(current_app.root_path, 'temp'))

    try:
        shutil.copy(db_path, temp_backup_path)
        return send_file(temp_backup_path, as_attachment=True, attachment_filename='attendance_backup.sqlite')
    except Exception as e:
        current_app.logger.error(f"Error during database export: {e}")
        flash("Failed to export the database.", "error")
        return redirect(url_for('admin.admin_dashboard'))  # Replace with your actual dashboard route
    finally:
        if os.path.exists(temp_backup_path):
            os.remove(temp_backup_path)


@admin_bp.route('/import_db', methods=['GET', 'POST'])
@login_required
@require_admin
def import_db():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):  # Implement allowed_file check for security
            filename = secure_filename(file.filename)
            config = current_app.config
            db_path = config['flask']['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            backup_path = os.path.join('temp', 'backup_db.sqlite')  # Backup the current database
            new_db_path = os.path.join('temp', filename)  # Path to store the new database

            if not os.path.exists('temp'):
                os.makedirs('temp')

            try:
                # Backup the current database
                shutil.copy(db_path, backup_path)
                # Save the new database file
                file.save(new_db_path)

                # Replace the current database with the new one
                shutil.copy(new_db_path, db_path)

                flash('Database imported successfully.', 'success')
                return redirect(url_for('admin.some_admin_route'))
            except Exception as e:
                current_app.logger.error(f"Error during database import: {e}")
                flash("Failed to import the database.", "error")
        else:
            flash("Invalid file format.", "error")

    return render_template('import_db.html')


def get_user_by_id(user_id):
    return User.query.get_or_404(user_id)


@admin_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        try:
            # Prepare the email message
            msg = MIMEText(form.message.data)
            msg['Subject'] = f"Feedback from {form.name.data}"
            msg['From'] = current_user.email
            msg['To'] = current_app.config['smtp']['SUPPORT_EMAIL']

            # Save the email to a temporary file
            temp_file = "/tmp/temp_email.txt"
            with open(temp_file, "w") as file:
                file.write(msg.as_string())

            # Send the email using msmtp
            command = f"cat {temp_file} | msmtp -t"
            subprocess.run(command, shell=True, check=True)

            flash('Thank you for your feedback!', 'success')
            return redirect(url_for('admin.admin_dashboard'))  # Redirect to homepage or appropriate page
        except subprocess.CalledProcessError as e:
            flash('An error occurred while sending your feedback.', 'error')
            current_app.logger.error(f"Failed to send feedback email: {e}")
        finally:
            # Clean up: remove the temporary email file
            if os.path.exists(temp_file):
                os.remove(temp_file)

    return render_template('feedback.html', form=form)
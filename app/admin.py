from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, session, send_file
from flask_login import login_required, current_user
from app.utils import delete_old_logs, get_lab_info
from app.models import db, User, IPLocation, TermDates, LogEntry, DatabaseLogHandler, LabMessage, SignInData, EmailTemplate
from app.forms import LoginForm, LogoutForm, AddUserForm, MessageForm, QuerySelectionForm, AddIPMappingForm, RemoveIPMappingForm, UploadCSVForm, TermDatesForm, ManageEmailsForm
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from io import StringIO

import logging
import traceback
import csv
import os
import itertools

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
        delete_old_logs()


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
    logout_form = LogoutForm()

    lab_info = get_lab_info(request.remote_addr)
    lab_location_name, lab_location_id = lab_info  # Unpack the tuple

    # Fetch the default lab ID
    default_lab = IPLocation.query.first()
    default_lab_id = default_lab.id if default_lab else None

    if current_user.is_authenticated:
        # Pass the is_admin variable and the IPLocation instance to the template
        return render_template('admin_dashboard.html', is_admin=current_user.is_admin, logout_form=logout_form,
                               lab_location_id=lab_location_id, default_lab_id=default_lab_id)
    else:
        flash('Please log in with an admin account to access this page.', 'error')
        return redirect(url_for('auth.login'))


# Query Selection #
###################

@admin_bp.route('/query_selection', methods=['GET', 'POST'])
@login_required
def query_selection():
    form = QuerySelectionForm()
    logout_form = LogoutForm()
    term_dates = TermDates.query.all()

    # Populate term date range choices
    form.term_date_range.choices = [(0, 'Select Term Date Range')] + [
        (td.id, f"{td.term_name}: {td.start_date.strftime('%Y-%m-%d')} to {td.end_date.strftime('%Y-%m-%d')}")
        for td in term_dates
    ]

    # Populate location choices with "Complete Term" option
    user_ip_locations = IPLocation.query.filter(
        IPLocation.mapped_users.any(User.id == current_user.id)
    ).all()
    form.location_name.choices = [('Complete Term', 'Complete Term')] + \
                                 [(loc.location_name, loc.location_name) for loc in user_ip_locations]

    data = None  # Initialize data to None

    if form.validate_on_submit():
        term_date = TermDates.query.get(form.term_date_range.data)

        if term_date:
            start_date = term_date.start_date
            end_date = term_date.end_date + timedelta(days=1)
            location_name = form.location_name.data

            if location_name == 'Complete Term':
                data = SignInData.query.filter(
                    SignInData.sign_in_timestamp.between(start_date, end_date)
                ).all()
            else:
                data = SignInData.query.filter(
                    SignInData.sign_in_timestamp.between(start_date, end_date),
                    SignInData.ip_location.has(IPLocation.location_name == location_name)
                ).all()
        
        if data:
            # Generate CSV
            csv_filename = f"attendance_data_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(["L Number", "Lab Location", "Class Selected", "Sign-in Timestamp", "Sign-out Timestamp", "Comments"])
            for entry in data:
                writer.writerow([entry.l_number, entry.lab_location, entry.class_selected, entry.sign_in_timestamp,
                                 entry.sign_out_timestamp, entry.comments])
            output.seek(0)

            # Save CSV data
            csv_folder = os.path.join(current_app.root_path, 'csv_files')
            if not os.path.exists(csv_folder):
                os.makedirs(csv_folder)
            csv_path = os.path.join(csv_folder, csv_filename)
            with open(csv_path, 'w', newline='') as f:
                f.write(output.getvalue())
            session['csv_filename'] = csv_filename

            return render_template('query_selection.html', form=form, term_dates=term_dates, logout_form=logout_form, csv_filename=csv_filename)

    return render_template('query_selection.html', form=form, term_dates=term_dates, logout_form=logout_form, csv_filename=None)


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
    logout_form = LogoutForm()
    add_user_form = AddUserForm()
    users = User.query.all()
    current_app.logger.debug('Users List: %s', users)

    ip_locations = IPLocation.query.all()


    return render_template('user_management.html', users=users, selected_user_id=selected_user_id, add_user_form=add_user_form, logout_form=logout_form, form=form,
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
    can_set_message = 'can_set_message' in request.form
    can_manage_email = 'can_manage_email' in request.form


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
        new_user.can_set_message = False  # Example
        new_user.can_manage_email = can_manage_email

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
        user = User.query.get_or_404(user_id)
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
    logout_form = LogoutForm()
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
    return render_template('term_dates_management.html', form=form, upload_csv_form=upload_csv_form, term_dates=term_dates, logout_form=logout_form)


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

@admin_bp.route('/set_message/<int:lab_location_id>', methods=['GET', 'POST'])
@login_required
def set_message(lab_location_id):
    if not current_user.can_set_message:
        flash('You do not have permission to set messages.', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    form = MessageForm()
    logout_form = LogoutForm()
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
        # Redirect with the correct lab_location_id
        return redirect(url_for('admin.set_message', lab_location_id=form.lab_location_id.data))

    lab_locations = current_user.ip_locations

    return render_template('set_message.html', form=form, logout_form=logout_form, lab_locations=lab_locations, lab_location_id=lab_location_id)


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


@admin_bp.route('/toggle_message_permission/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def toggle_message_permission(user_id, redirect_enabled=True):
    try:
        current_app.logger.info(f"Attempting to toggle message permission for user ID: {user_id}")
        user = User.query.get(user_id)
        if user is None:
            current_app.logger.warning(f"User ID {user_id} not found.")
            flash('User not found.', 'error')
            return redirect(url_for('admin.user_management'))

        user.can_set_message = not user.can_set_message
        db.session.commit()
        current_app.logger.info(f"Message permission toggled for user ID: {user_id}.")
        flash('Message permission toggled.', 'success')
    except Exception as e:
        current_app.logger.error(f"Error toggling message permission for user ID {user_id}: {e}", exc_info=True)
        db.session.rollback()
        flash(f'Error toggling message permission: {e}', 'error')

    if redirect_enabled:
        return redirect(url_for('admin.user_management'))
    
    return redirect(url_for('admin.user_management'))


## IP MAPPING MANAGEMENT ##
##########################
@admin_bp.route('/ip-management', methods=['GET', 'POST'])
@login_required
@require_admin
def ip_management():
    add_ip_form = AddIPMappingForm()
    remove_ip_form = RemoveIPMappingForm()
    logout_form = LogoutForm()

    # Populate choices for remove_ip_form's remove_ip_id field
    ip_locations = IPLocation.query.all()
    remove_ip_form.remove_ip_id.choices = [(ip.id, f"{ip.ip_address} - {ip.location_name}") for ip in ip_locations]

    if request.method == 'POST':
        if add_ip_form.validate_on_submit():
            # Logic to add an IP mapping
            new_ip_location = IPLocation(
                ip_address=add_ip_form.ip_address.data,
                location_name=add_ip_form.location_name.data
            )
            db.session.add(new_ip_location)
            try:
                db.session.commit()
                flash('IP mapping added successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error adding IP mapping: {e}', 'error')
            # Redirect to refresh the form and choices
            return redirect(url_for('admin.ip_management'))

        elif remove_ip_form.validate_on_submit():
            # Logic to remove an IP mapping
            selected_ip_id = remove_ip_form.remove_ip_id.data
            ip_location = IPLocation.query.get(selected_ip_id)
            if ip_location:
                db.session.delete(ip_location)
                db.session.commit()
                flash('IP mapping removed successfully.', 'success')
            else:
                flash('Selected IP mapping not found.', 'error')
            # Redirect to refresh the form and choices
            return redirect(url_for('admin.ip_management'))
        else:
            # Handle form validation errors for both forms
            flash('Form validation error.', 'error')

    # Render the template with the forms
    return render_template('ip_management.html', add_ip_form=add_ip_form, remove_ip_form=remove_ip_form, logout_form=logout_form, ip_mappings=ip_locations)


@admin_bp.route('/admin/assign_ip_mappings', methods=['POST'])
@login_required
@require_admin
def assign_ip_mappings():
    selected_user_id = request.form.get('selected_user_id')
    user = User.query.get_or_404(selected_user_id)

    # Update user's IP mappings
    selected_ip_mappings_ids = request.form.getlist('selected_ip_mappings')
    user.ip_locations.clear()
    for ip_id in selected_ip_mappings_ids:
        ip_location = IPLocation.query.get(ip_id)
        if ip_location:
            user.ip_locations.append(ip_location)

    # Toggle permissions
    user.can_set_message = 'can_set_message' in request.form
    user.can_manage_email = 'can_manage_email' in request.form

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
    user = User.query.get_or_404(user_id)
    assigned_ips = [ip_location.id for ip_location in user.ip_locations]

    # Add the user's message and email permission states to the response
    user_details = {
        'assignedIps': assigned_ips,
        'canSetMessage': user.can_set_message,
        'canManageEmail': user.can_manage_email
    }
    return jsonify(user_details)


## LOG DATA PAGE ##
###################

# Function to add an INFO logging page 
@admin_bp.route('/logs')
@login_required
@require_admin
def view_logs():
    logout_form = LogoutForm()

    page = request.args.get('page', 1, type=int)  # Get the current page number
    per_page = 10  # Set the number of logs per page

    # Use paginate method correctly
    logs_pagination = LogEntry.query.order_by(LogEntry.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # Pass logs_pagination to the template
    return render_template('view_logs.html', logs_pagination=logs_pagination, logout_form=logout_form)


# Function to start the logging 
def setup_logging(app):
    log_handler = DatabaseLogHandler()
    log_handler.setLevel(logging.INFO)  # Set the log level you want to capture
    app.logger.addHandler(log_handler)


@admin_bp.route('/download_csv/<filename>')
@login_required
@require_admin
def download_csv(filename):
    # Make sure the filename is safe
    if '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400

    # Update the path to the csv_files folder
    csv_folder = os.path.join(current_app.root_path, 'csv_files')
    csv_path = os.path.join(csv_folder, filename)
    
    if os.path.exists(csv_path):
        return send_file(csv_path, as_attachment=True, mimetype='text/csv', download_name=filename)
    else:
        flash('No CSV data found. Please generate the report again.', 'error')
        return redirect(url_for('admin.query_selection'))


@admin_bp.route('/download_logs')
@login_required
@require_admin
def download_logs():
    try:
        # Generate a filename for the CSV
        csv_folder = os.path.join(current_app.root_path, 'logs')
        if not os.path.exists(csv_folder):
            os.makedirs(csv_folder)
        csv_filename = "logs.csv"
        csv_path = os.path.join(csv_folder, csv_filename)
        
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'user', 'level', 'message'])
            
            logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).all()
            for log in logs:
                writer.writerow([
                    log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    log.user.username if log.user else 'System',
                    log.level,
                    log.message
                ])

        current_app.logger.info(f"CSV file path: {csv_path}")
        if os.path.exists(csv_path):
            current_app.logger.info("CSV file exists, ready for download.")
        else:
            current_app.logger.error("CSV file does not exist.")

        # Add the filename to the session or another way to retrieve it
        session['log_csv_filename'] = csv_filename

        # Redirect or render a template with a link to download the file
        return send_file(csv_path, as_attachment=True)
    except Exception as e:
        current_app.logger.error(f"Error in downloading logs: {e}")
        flash('Log file not found', 'error')
        return redirect(url_for('admin.view_logs'))
    
# Welcome Email Management #
############################

@admin_bp.route('/manage_emails/<int:lab_id>', methods=['GET', 'POST'])
@login_required
@require_admin
def manage_emails(lab_id):
    form = ManageEmailsForm()
    logout_form = LogoutForm()
    lab_location = IPLocation.query.get_or_404(lab_id)
    email_template = lab_location.email_template

    if request.method == 'POST' and form.validate_on_submit():
        if email_template:
            email_template.subject = form.subject.data
            email_template.body = form.body.data
        else:
            email_template = EmailTemplate(subject=form.subject.data, body=form.body.data, lab_location_id=lab_id)
            db.session.add(email_template)

        # Update the welcome_email_enabled status
        lab_location.welcome_email_enabled = 'enable_email' in request.form
        db.session.commit()
        flash('Email settings updated successfully', 'success')
        return redirect(url_for('admin.manage_emails', lab_id=lab_id))

    if email_template:
        form.subject.data = email_template.subject
        form.body.data = email_template.body

    enable_email = lab_location.welcome_email_enabled if lab_location else False
    return render_template('manage_emails.html', form=form, logout_form=logout_form, lab_location=lab_location, lab_id=lab_id, enable_email=lab_location.welcome_email_enabled)


@admin_bp.route('/get_user_details/<int:user_id>')
@login_required
@require_admin
def get_user_details(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    assigned_ips = [ip_location.id for ip_location in user.ip_locations]
    return jsonify({
        'assignedIps': assigned_ips, 
        'enableWelcomeEmail': user.can_send_welcome_email
    })


@admin_bp.route('/toggle_email_permission/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def toggle_email_permission(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.can_manage_email = not user.can_manage_email
    db.session.commit()
    flash(f'Email management permission for {user.username} toggled.', 'success')
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/update_user_settings/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def update_user_settings(user_id):
    user = User.query.get_or_404(user_id)
    data = request.json

    user.can_set_message = data['canSetMessage']
    user.can_manage_email = data['canManageEmail']

    try:
        db.session.commit()
        return jsonify({'message': 'User settings updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
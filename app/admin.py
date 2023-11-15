from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, session, send_file
from flask_login import login_required, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from bleach import clean
from app.main import get_lab_info
from app.models import db, User, IPLocation, TermDates, LogEntry, DatabaseLogHandler, LabMessage, SignInData
from app.forms import LoginForm, LogoutForm, AddUserForm, MessageForm, QuerySelectionForm, AddIPMappingForm, RemoveIPMappingForm, TermDatesForm
from .config import load_config
from functools import wraps
from datetime import datetime, timedelta
from io import StringIO
from flask_paginate import Pagination, get_page_args
from tempfile import NamedTemporaryFile


import logging
import traceback
import csv
import os
import itertools


admin_bp = Blueprint('admin', __name__)


# Decorator to require admin access
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied: You do not have the necessary permissions.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


# Function to sign out students, who are not signed out after 4:30pm using APScheduler
def sign_out_previous_day_students():
    """Sign out students who signed in the previous day and haven't signed out yet."""
    yesterday = (datetime.now() - datetime.timedelta(days=1)).date()
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


# Start the APScheduler for log deletion and signing students out at 4:30
def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=delete_old_logs, trigger="cron", hour=1, minute=0)
    scheduler.add_job(func=sign_out_task, trigger='cron', hour=16, minute=36)
    scheduler.start()


# Function to create an admin to start off
def create_admin(app):
    with app.app_context():
        # Load the configuration
        config = current_app.config

        ip_mapping_form = AddIPMappingForm()

        if request.method == 'POST':
            current_app.logger.debug('POST data: %s', request.form)

        if ip_mapping_form.validate_on_submit():
            new_ip_mapping = IPLocation(
                ip=ip_mapping_form.ip.data,
                location_name=ip_mapping_form.location_name.data
            )
            db.session.add(new_ip_mapping)
            try:
                db.session.commit()
                flash('New IP mapping added.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {e}', 'error')

        # Now you can access the configuration items
        default_admin_password = config['encryption']['DEFAULT_ADMIN_PASSWORD']
        default_admin_username = config['encryption']['DEFAULT_ADMIN_USERNAME']
        default_admin_email = config['encryption']['DEFAULT_ADMIN_EMAIL']

        # Check if admin user already exists
        existing_admin = User.query.filter_by(username=default_admin_username).first()
        if not existing_admin:
            # Create an admin user with a default password
            admin_user = User(
                username=default_admin_username,
                email=default_admin_email,
                is_admin=True
            )
            admin_user.set_password(default_admin_password)
            db.session.add(admin_user)
            db.session.commit()


# Function to sign in to the admin dashboard
@admin_bp.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    logout_form = LogoutForm()

    lab_info = get_lab_info(request.remote_addr)
    lab_location_name, lab_location_id = lab_info  # Unpack the tuple

    if current_user.is_authenticated:
        # Pass the is_admin variable and the IPLocation instance to the template
        return render_template('admin_dashboard.html', is_admin=current_user.is_admin, logout_form=logout_form,
                               lab_location_id=lab_location_id)
    else:
        flash('Please log in with an admin account to access this page.', 'error')
        return redirect(url_for('auth.login'))


## Query Selection ##
#####################

@admin_bp.route('/query_selection', methods=['GET', 'POST'])
@login_required
def query_selection():
    form = QuerySelectionForm()
    logout_form = LogoutForm()

    term_dates = TermDates.query.all()

    # Populate the term_date_range choices
    form.term_date_range.choices = [(0, 'Select Term Date Range')] + [
        (td.id, f"{td.term_name}: {td.start_date.strftime('%Y-%m-%d')} to {td.end_date.strftime('%Y-%m-%d')}")
        for td in term_dates
    ]

    if form.validate_on_submit():
        term_date = TermDates.query.get(form.term_date_range.data) if form.term_date_range.data else None

        if term_date:
            start_date = term_date.start_date
            end_date = term_date.end_date + timedelta(days=1)
            end_date_file = term_date.end_date
        else:
            start_date = form.start_date.data
            end_date = form.end_date.data
            end_date_file = end_date

            if start_date and end_date:
                end_date += timedelta(days=1)

            else:
                flash('Please specify start and end dates.', 'error')
                return render_template('query_selection.html', form=form, logout_form=logout_form, csv_filename=None)
        
        # Fetch data from DB
        data = SignInData.query.filter(
            SignInData.sign_in_timestamp >= start_date,
            SignInData.sign_in_timestamp < end_date
        ).all()

        # Generate a unique filename for the CSV
        csv_filename = f"attendance_data_{start_date.strftime('%Y-%m-%d')}_{end_date_file.strftime('%Y-%m-%d')}.csv"

        output = StringIO()
        writer = csv.writer(output)
        # ... writing to CSV logic ...

        # Define the path for the csv_files directory
        csv_folder = os.path.join(current_app.root_path, 'csv_files')
        if not os.path.exists(csv_folder):
            os.makedirs(csv_folder)

        # Save the CSV data in the csv_files folder
        csv_path = os.path.join(csv_folder, csv_filename)
        with open(csv_path, 'w', newline='') as f:
            f.write(output.getvalue())

        # Store the filename in the session for retrieval
        session['csv_filename'] = csv_filename

        # Add the filename to the template context
        return render_template('query_selection.html', form=form, logout_form=logout_form, data=data, term_dates=term_dates, csv_filename=csv_filename)

    else:
        if request.method == 'POST':
            flash('Form submission is invalid', 'error')

    # If it's a GET request or the POST request is processed, show the same query selection page without the download link
    return render_template('query_selection.html', form=form, logout_form=logout_form, csv_filename=None)


## ADMIN USER MANAGEMENT #
##########################

@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
@require_admin
def user_management():
    form = LoginForm()
    logout_form = LogoutForm()
    add_user_form = AddUserForm()
    users = User.query.all()
    current_app.logger.debug('Users List: %s', users)

    ip_locations = IPLocation.query.all()

    if request.method == 'POST':
        current_app.logger.debug('POST data: %s', request.form)
        add_user_form

    return render_template('user_management.html', users=users, add_user_form=add_user_form, logout_form=logout_form, form=form,
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
    can_access_query_selection = 'can_access_query_selection' in request.form

    if not (username and email and password):
        flash('Please enter all the required fields.', 'error')
        return redirect(url_for('admin.user_management'))

    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        flash('A user with this email or username already exists.', 'error')
    else:
        new_user = User(
            username=username,
            email=email,
            is_admin=is_admin,
            can_set_message=can_set_message,
            can_access_query_selection=can_access_query_selection
        )
        new_user.set_password(password)
        try:
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


@admin_bp.route('/apply_bulk_actions', methods=['POST'])
@login_required
@require_admin
def apply_bulk_actions():
    selected_user_ids = request.form.getlist('selected_users')
    action = request.form.get('action')

    if not selected_user_ids:
        flash('No users selected.', 'error')
        return redirect(url_for('admin.user_management'))

    if action == 'toggle_message':
        for user_id in selected_user_ids:
            toggle_message_permission(user_id, redirect_enabled=False)
    elif action == 'remove_users':
        for user_id in selected_user_ids:
            remove_user(user_id, redirect_enabled=False)
    elif action == 'cycle_ip_mapping':
        for user_id in selected_user_ids:
            cycle_ip_mapping(user_id, redirect_enabled=False)
    # ... handle other actions ...

    flash('Bulk actions applied successfully.', 'success')
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/cycle_ip_mapping/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def cycle_ip_mapping(user_id, redirect_enabled=True):
    user = User.query.get_or_404(user_id)
    
    all_ip_ids = [ip.id for ip in IPLocation.query.all()]
    current_mappings = set([ip.id for ip in user.ip_locations])
    all_combinations = sum([list(itertools.combinations(all_ip_ids, i)) for i in range(len(all_ip_ids) + 1)], [])
    
    # Find the index of the current combination
    current_index = next((idx for idx, comb in enumerate(all_combinations) if set(comb) == current_mappings), -1)
    
    # Calculate the index of the next combination
    next_index = (current_index + 1) % len(all_combinations)
    
    # Update the user's IP mappings
    user.ip_locations = [IPLocation.query.get(ip_id) for ip_id in all_combinations[next_index]]
    db.session.commit()
    
    flash('User IP mapping updated successfully.', 'success')

    if redirect_enabled:
        return redirect(url_for('admin.user_management'))

    return None  # Or an appropriate response when redirect is disabled


## TERM DATES MANAGEMENT ##
##########################

@admin_bp.route('/term_dates_management', methods=['GET', 'POST'])
@login_required
@require_admin
def term_dates_management():
    form = TermDatesForm()
    logout_form = LogoutForm()

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
    return render_template('term_dates_management.html', form=form, term_dates=term_dates, logout_form=logout_form)


def determine_term_name(start_date):
    month = start_date.month
    year = start_date.year
    if month == 1:  # January
        term_name = f'Winter {year}'
    elif month == 3:  # March
        term_name = f'Spring {year}'
    elif month == 5:  # June
        term_name = f'Summer {year}'
    elif month == 9:  # June
        term_name = f'Fall {year}'
    return term_name


@admin_bp.route('/delete_term_date/<int:term_date_id>', methods=['POST'])
@login_required
@require_admin
def delete_term_date(term_date_id):
    term_date = TermDates.query.get_or_404(term_date_id)
    try:
        db.session.delete(term_date)
        db.session.commit()
        flash('Term date deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'error')

    return redirect(url_for('admin.term_dates_management'))




## SET MESSAGE MANAGEMENT ##
############################

@admin_bp.route('/set_message/<int:lab_location_id>', methods=['GET', 'POST'])
@login_required
def set_message(lab_location_id):
    form = MessageForm()
    logout_form = LogoutForm()  # Ensure logout_form is instantiated
    form.lab_location_id.choices = [(loc.id, loc.location_name) for loc in IPLocation.query.all()]

    if form.validate_on_submit():
        message = LabMessage(
            content=form.content.data,
            lab_location_id=form.lab_location_id.data,
            user_id=current_user.id
        )
        db.session.add(message)
        db.session.commit()
        flash('Your message has been posted.', 'success')
        return redirect(url_for('admin.admin_dashboard'))

    lab_locations = IPLocation.query.all()
    return render_template('set_message.html', form=form, logout_form=logout_form, lab_locations=lab_locations)


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

    return render_template('ip_management.html', add_ip_form=add_ip_form, remove_ip_form=remove_ip_form,
                           logout_form=logout_form, ip_mappings=IPLocation.query.all())


@admin_bp.route('/update_user_ip_mapping/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def update_user_ip_mapping(user_id):
    user = User.query.get_or_404(user_id)
    
    # Get all IP mappings
    ip_mappings = [None] + [ip.id for ip in IPLocation.query.all()]
    
    # Find current mapping index
    current_index = ip_mappings.index(user.ip_location_id) if user.ip_location_id in ip_mappings else -1
    
    # Calculate next index
    next_index = (current_index + 1) % len(ip_mappings)
    
    # Update user's IP mapping
    user.ip_location_id = ip_mappings[next_index]
    db.session.commit()
    
    flash('User IP mapping updated successfully.', 'success')
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/remove_user_ip_mapping/<int:user_id>', methods=['POST'])
@login_required
@require_admin
def remove_user_ip_mapping(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
    else:
        # Set the user's IP mapping to None
        user.ip_location_id = None
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
@admin_bp.route('/remove_ip_mapping/<int:ip_id>', methods=['POST'])
@login_required
@require_admin
def remove_ip_mapping(ip_id):
    ip_mapping = IPLocation.query.get_or_404(ip_id)
    # Make sure to handle associated messages if any
    messages = LabMessage.query.filter_by(lab_location_id=ip_id).all()
    for message in messages:
        db.session.delete(message)
    try:
        db.session.delete(ip_mapping)
        db.session.commit()
        flash('IP mapping removed successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while removing the IP mapping: {e}', 'error')

    return redirect(url_for('admin.ip_management'))


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


# Function to delete logs from the logging page every 14 days using APScheduler
def delete_old_logs():
    threshold_date = datetime.utcnow() - datetime.timedelta(days=14)
    LogEntry.query.filter(LogEntry.timestamp <= threshold_date).delete()
    db.session.commit()


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
        return send_file(csv_path, as_attachment=True)
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
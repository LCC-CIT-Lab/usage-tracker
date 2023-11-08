from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_login import login_required, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from app.main import get_lab_info
from app.models import db, User, IPLocation, TermDates, LogEntry, DatabaseLogHandler, LabMessage
from app.forms import LoginForm, LogoutForm, AddIPMappingForm, TermDatesForm, RemoveIPMappingForm
from .config import load_config

import logging
import traceback

admin_bp = Blueprint('admin', __name__)


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

@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    form = LoginForm()
    logout_form = LogoutForm()
    users = User.query.all()
    current_app.logger.debug('Users List: %s', users)

    ip_locations = IPLocation.query.all()
    
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        current_app.logger.debug('POST data: %s', request.form)

        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form  # This will be True if the Admin checkbox is checked
        can_set_message = 'can_set_message' in request.form
        can_access_query_selection = 'can_access_query_selection' in request.form

        # Perform input validation
        if not (username and email and password):
            flash('Please enter all the required fields.', 'error')
        else:
            # Check if user already exists
            existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
            if existing_user:
                flash('A user with this email or username already exists.', 'error')
            else:
                try:
                    # Create a new user
                    new_user = User(
                        username=username,
                        email=email,
                        is_admin=is_admin,
                        can_set_message=can_set_message,
                        can_access_query_selection=can_access_query_selection
                    )
                    new_user.set_password(password)  # Hashing the password here
                    db.session.add(new_user)
                    db.session.commit()

                except Exception as e:
                    db.session.rollback()
                    traceback_str = traceback.format_exc()  # This will give you the full traceback as a string.
                    current_app.logger.error(traceback_str)  # This will log the full traceback.
                    flash(f'An error occurred while creating the user: {e}', 'error')

    return render_template('user_management.html', users=users, logout_form=logout_form, form=form, ip_locations=ip_locations)


@admin_bp.route('/term_dates_management', methods=['GET', 'POST'])
@login_required
def term_dates_management():
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('auth.login'))

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
    if month in range(1, 4):  # January to March
        term_name = f'Winter {year}'
    elif month in range(4, 7):  # April to June
        term_name = f'Spring {year}'
    elif month in range(7, 10):  # July to September
        term_name = f'Summer {year}'
    else:  # October to December
        term_name = f'Fall {year}'
    return term_name


@admin_bp.route('/delete_term_date/<int:term_date_id>', methods=['POST'])
@login_required
def delete_term_date(term_date_id):
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.', 'error')
        return redirect(url_for('auth.login'))

    term_date = TermDates.query.get_or_404(term_date_id)
    try:
        db.session.delete(term_date)
        db.session.commit()
        flash('Term date deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'error')

    return redirect(url_for('admin.term_dates_management'))

    
@admin_bp.route('/update_user_ip_mapping/<int:user_id>', methods=['POST'])
@login_required
def update_user_ip_mapping(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.user_management'))

    new_ip_location_id = request.form.get('ip_mapping_id')
    if new_ip_location_id:
        # Ensure the new ID is either a valid ID or an empty string which is intended to unset the mapping.
        new_ip_location = IPLocation.query.get(new_ip_location_id)
        if new_ip_location or new_ip_location_id == '':
            user.ip_location_id = new_ip_location_id if new_ip_location else None
            db.session.commit()
            flash('User IP mapping updated successfully.', 'success')
        else:
            flash('Invalid IP location ID.', 'error')
    else:
        flash('No IP mapping selected.', 'error')

    return redirect(url_for('admin.user_management'))


@admin_bp.route('/toggle_message_permission/<int:user_id>', methods=['POST'])
@login_required
def toggle_message_permission(user_id):
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
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/remove_user_ip_mapping/<int:user_id>', methods=['POST'])
@login_required
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


@admin_bp.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('auth.login'))

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
            flash(f'An error occurred while creating the user: {e}', 'error')

    return redirect(url_for('admin.user_management'))


@admin_bp.route('/remove_user/<int:user_id>', methods=['POST'])
@login_required
def remove_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        current_app.logger.info(f"Attempting to remove user with ID: {user_id}")

        # The check for admin users with default passwords has been removed.
        # If you still want to log this event, you can keep the log message:
        if user.is_admin and user.is_default_password:
            current_app.logger.info(f"Removing admin user with default password, user ID: {user_id}")

        db.session.delete(user)
        db.session.commit()
        flash('User removed successfully.', 'success')
        current_app.logger.info(f"User with ID {user_id} removed successfully.")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error removing user with ID {user_id}: {e}", exc_info=True)
        flash(f'Error removing user: {e}', 'error')
    
    return redirect(url_for('admin.user_management'))


@admin_bp.route('/logs')
@login_required
def view_logs():
    logout_form = LogoutForm()

    if not current_user.is_admin:
        flash('You do not have permission to view the logs.', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(100).all()  # Fetch the latest 100 logs
    return render_template('view_logs.html', logs=logs, logout_form=logout_form)


def delete_old_logs():
    threshold_date = datetime.utcnow() - timedelta(days=14)
    LogEntry.query.filter(LogEntry.timestamp <= threshold_date).delete()
    db.session.commit()


def sign_out_previous_day_students():
    """Sign out students who signed in the previous day and haven't signed out yet."""
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


def sign_out_task():
    from app import create_app
    app = create_app()  # Create an instance of the app
    with app.app_context():
        sign_out_previous_day_students()
        delete_old_logs()

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=delete_old_logs, trigger="cron", hour=1, minute=0)
    scheduler.add_job(func=sign_out_task, trigger='cron', hour=1, minute=0)
    scheduler.start()

# Call start_scheduler() when your application starts

def setup_logging(app):
    log_handler = DatabaseLogHandler()
    log_handler.setLevel(logging.INFO)  # Set the log level you want to capture
    app.logger.addHandler(log_handler)
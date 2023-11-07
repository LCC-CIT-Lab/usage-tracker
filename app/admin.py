from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app.models import db, User, IPLocation
from app.forms import LoginForm, LogoutForm, AddIPMappingForm, RemoveIPMappingForm
from .config import load_config

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

    if not current_user.is_admin:
        flash('Access denied: You do not have admin privileges.', 'error')
        return redirect(url_for('main.landing'))

    return render_template('admin_dashboard.html', logout_form=logout_form)

@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    form = LoginForm()
    logout_form = LogoutForm()

    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
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

    users = User.query.all()
    ip_locations = IPLocation.query.all()
    print(ip_locations)  # Add this line for debugging purposes

    return render_template('user_management.html', users=users, logout_form=logout_form, form=form, ip_locations=ip_locations)

@admin_bp.route('/update_user_permissions/<int:user_id>', methods=['POST'])
@login_required
def update_user_permissions(user_id):
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('auth.login'))

    user_to_update = User.query.get_or_404(user_id)
    print(f"Before updates: can_set_message={user_to_update.can_set_message}, ip_location_id={user_to_update.ip_location_id}")

    if 'toggle_can_set_message' in request.form:
        user_to_update.can_set_message = not user_to_update.can_set_message
        flash('User message permission updated.')

    if 'update_ip_mapping' in request.form and 'ip_mapping_name' in request.form:
        ip_mapping_id = int(request.form.get('ip_mapping_name')) if request.form.get('ip_mapping_name') else None
        user_to_update.ip_location_id = ip_mapping_id
        flash('User IP mapping updated.')

    try:
        print(f"After updates: can_set_message={user_to_update.can_set_message}, ip_location_id={user_to_update.ip_location_id}")
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'error')

    return redirect(url_for('admin.user_management'))

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied: You do not have admin privileges.', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    user_to_delete = User.query.get_or_404(user_id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the user: {e}', 'error')

    return redirect(url_for('admin.user_management'))
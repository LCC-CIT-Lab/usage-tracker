from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from app.models import db, User, LabLocation
from app.auth import generate_token, validate_token
from app.forms import LoginForm, AddLocationForm, RemoveLocationForm, AdminDashboardForm
from .config import load_config

import traceback

admin_bp = Blueprint('admin', __name__)

def create_admin(app):
    with app.app_context():
        # Load the configuration
        config = current_app.config
        
        # Now you can access the configuration items
        default_admin_password = config['encryption']['DEFAULT_ADMIN_PASSWORD']
        admin_username = 'admin'  # Replace with desired admin username
        admin_email = 'admin@example.com'  # Replace with the admin email

        # Check if admin user already exists
        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            # Create an admin user with a default password
            admin_user = User(
                username=admin_username,
                email=admin_email,
                is_admin=True
            )
            admin_user.set_password(default_admin_password)
            db.session.add(admin_user)
            db.session.commit()

@admin_bp.cli.command('create-admin')
def create_admin_command():
    """Create the admin user."""
    create_admin(current_app._get_current_object())
    print("Admin user created.")

@admin_bp.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    form = AdminDashboardForm()
    form.remove_lab_location.choices = [(location.id, location.name) for location in LabLocation.query.all()]
    
    if not current_user.is_admin:
        flash('Access denied: You do not have admin privileges.')
        return redirect(url_for('main.landing'))

    if form.validate_on_submit():
        if form.add_submit.data:  # Check if the add button was pressed
            location_name = form.new_lab_location.data
            if not LabLocation.query.filter_by(name=location_name).first():
                new_location = LabLocation(name=location_name)
                db.session.add(new_location)
                db.session.commit()
                flash('New location added.')
                # Refresh the choices to include the new location
                form.remove_lab_location.choices = [(location.id, location.name) for location in LabLocation.query.all()]
                print("New location added:", new_location.name)
                current_app.logger.info(f"New location added: {new_location.name}")
            else:
                flash('Location already exists.')

        elif form.remove_submit.data:  # Check if the remove button was pressed
            location_id = form.remove_lab_location.data
            location = LabLocation.query.get(location_id)
            if location:
                db.session.delete(location)
                db.session.commit()
                flash('Location removed.')
                # Refresh the choices to exclude the removed location
                form.remove_lab_location.choices = [(location.id, location.name) for location in LabLocation.query.all()]
                print("Location removed:", location.name)
                current_app.logger.info(f"Location removed: {location.name}")
            else:
                flash('Location not found.')

        # Redirecting to the same route to refresh the form and page
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_dashboard.html', form=form)

@admin_bp.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    form = LoginForm()
    if not current_user.is_admin:
        flash('Access denied: You do not have the necessary permissions.')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form  # This will be True if the Admin checkbox is checked

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
                        is_admin=is_admin
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
    return render_template('user_management.html', users=users, form=form)

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

@admin_bp.route('/add_location', methods=['GET', 'POST'])
@login_required
def add_location():
    form = AddLocationForm()
    if form.validate_on_submit():
        location_name = form.name.data
        if LabLocation.query.filter_by(name=location_name).first():
            flash('Location already exists.')
            return redirect(url_for('admin.add_location'))
        new_location = LabLocation(name=location_name)
        db.session.add(new_location)
        db.session.commit()
        flash('New location added.')
        return redirect(url_for('admin.dashboard'))
    return render_template('add_location.html', form=form)

@admin_bp.route('/remove_location', methods=['GET', 'POST'])
@login_required
def remove_location():
    form = RemoveLocationForm()
    form.location.choices = [(location.id, location.name) for location in LabLocation.query.all()]
    if form.validate_on_submit():
        location_id = form.location.data
        location = LabLocation.query.get(location_id)
        if location:
            db.session.delete(location)
            db.session.commit()
            flash('Location removed.')
        else:
            flash('Location not found.')
        return redirect(url_for('admin.dashboard'))
    return render_template('remove_location.html', form=form)
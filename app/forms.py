from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, HiddenField, PasswordField
from wtforms.validators import DataRequired, InputRequired
from wtforms.fields import DateField
from app.models import SignInData, LabLocation

class CSRFProtectForm(FlaskForm):
    # Used only for CSRF protection
    pass

class LandingForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()])
    csrf_token = HiddenField()

class SignInForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()], render_kw={'readonly': True})
    lab_location = SelectField('Lab Location', coerce=int, validators=[DataRequired()])
    class_selected = SelectField('Class', coerce=str, validators=[DataRequired()], choices=[])

    lab_location = SelectField('Lab Location', coerce=int)

    def __init__(self, *args, **kwargs):
        super(SignInForm, self).__init__(*args, **kwargs)
        self.populate_lab_locations()

    def populate_lab_locations(self):
        self.lab_location.choices = [(location.id, location.name) for location in LabLocation.query.all()]

class SignOutForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()])
    comment = StringField('Comment')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class QuerySelectionForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Generate Report')

class AdminDashboardForm(FlaskForm):
    new_lab_location = StringField('New Lab Location', validators=[DataRequired()])
    remove_lab_location = SelectField('Remove Lab Location', coerce=int)
    add_submit = SubmitField('Add Location')
    remove_submit = SubmitField('Remove Location')

class AddLocationForm(FlaskForm):
    name = StringField('Location Name', validators=[DataRequired()])
    submit = SubmitField('Add Location')

class RemoveLocationForm(FlaskForm):
    location = SelectField('Location', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Remove Location')

# ... Add other form classes as needed

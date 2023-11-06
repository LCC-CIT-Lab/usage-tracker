from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, HiddenField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, InputRequired, IPAddress
from wtforms.fields import DateField
from app.models import SignInData

class CSRFProtectForm(FlaskForm):
    # Used only for CSRF protection
    pass

class LandingForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()])
    csrf_token = HiddenField()

class SignInForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()], render_kw={'readonly': True})
    class_selected = SelectField('Class', coerce=str, validators=[DataRequired()], choices=[])

    def __init__(self, *args, **kwargs):
        super(SignInForm, self).__init__(*args, **kwargs)

class SignOutForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()])
    comment = StringField('Comment')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class LogoutForm(FlaskForm):
    submit = SubmitField('Logout')

class QuerySelectionForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Generate Report')

class AddIPMappingForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    location_name = StringField('Location Name', validators=[DataRequired()])
    submit = SubmitField('Add IP Mapping')

class RemoveIPMappingForm(FlaskForm):
    remove_location_name = StringField('Location Name to Remove', validators=[DataRequired()])
    remove_submit = SubmitField('Remove IP Mapping')

class MessageForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Set Message')

# ... Add other form classes as needed

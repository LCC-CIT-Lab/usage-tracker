from flask_wtf import FlaskForm
from wtforms import RadioField, StringField, SelectField, SubmitField, HiddenField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, InputRequired, IPAddress, Optional
from wtforms.fields import DateField
from flask_wtf.file import FileField, FileAllowed, FileRequired


class CSRFProtectForm(FlaskForm):
    # Used only for CSRF protection
    pass


class LandingForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()])
    csrf_token = HiddenField()


class SignInForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()], render_kw={'readonly': True})
    class_selected = RadioField('Class', coerce=str, validators=[DataRequired()], choices=[])

    def __init__(self, *args, **kwargs):
        super(SignInForm, self).__init__(*args, **kwargs)
        self.class_selected.choices = []  # Initialize with empty list


class SignOutForm(FlaskForm):
    l_number = StringField('L Number', validators=[DataRequired()])
    comment = StringField('Comment')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


class LogoutForm(FlaskForm):
    submit = SubmitField('Logout')


class AddUserForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    location_name = StringField('Location Name', validators=[DataRequired()])
    submit = SubmitField('Add IP Mapping')


class QuerySelectionForm(FlaskForm):
    term_date_range = SelectField('Term Date Range', choices=[])
    start_date = DateField('Start Date', validators=[Optional()])
    end_date = DateField('End Date', validators=[Optional()])
    submit = SubmitField('Generate Report')
    location_name = SelectField('Location or Complete Term', coerce=str, validators=[Optional()])


    def validate(self, **kwargs):
        # If term_date_range is set, don't validate start_date and end_date
        if self.term_date_range.data:
            self.start_date.validators = [Optional()]
            self.end_date.validators = [Optional()]
        else:
            self.start_date.validators = [DataRequired()]
            self.end_date.validators = [DataRequired()]

        return super(QuerySelectionForm, self).validate(**kwargs)


class AddIPMappingForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    location_name = StringField('Location Name', validators=[DataRequired()])
    submit = SubmitField('Add IP Mapping')


class RemoveIPMappingForm(FlaskForm):
    remove_ip_id = SelectField('IP Location', coerce=int)
    remove_submit = SubmitField('Remove IP Mapping')


class TermDatesForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Add Term Dates')


class UploadCSVForm(FlaskForm):
    csv_file = FileField('CSV File', validators=[FileRequired(), FileAllowed(['csv'], 'CSV files only')])
    submit = SubmitField('Upload CSV')


class MessageForm(FlaskForm):
    lab_location_id = SelectField('Lab Location', coerce=int)
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Post Message')


# ... Add other form classes as needed

from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

import csv
import toml

# Load configurations from config.toml
config = toml.load('config.toml')

app = Flask(__name__)

# Apply configurations to Flask app
app.config.from_mapping(config['flask'])

db = SQLAlchemy(app)


# Database Model
class SignInData(db.Model):
    l_number = db.Column(db.String, primary_key=True)
    lab_location = db.Column(db.String, nullable=False)
    class_selected = db.Column(db.String, nullable=False)
    sign_in_timestamp = db.Column(db.DateTime, nullable=False)
    sign_out_timestamp = db.Column(db.DateTime)
    comments = db.Column(db.Text)


@app.route('/', methods=['GET', 'POST'])
def landing():
    if request.method == 'POST':
        l_number = request.form.get('l_number')
        # Simulate SSHfs integration by reading a local TSV file
        with open('students.tsv', 'r') as file:
            reader = csv.reader(file, delimiter='\t')
            for row in reader:
                if l_number == row[0]:  # Assuming L number is the first column
                    classes = row[1:]  # All columns after L number are classes
                    return redirect(url_for('sign_in', l_number=l_number, classes=classes))
        flash('Invalid L number', 'danger')
    return render_template('landing.html')


@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    l_number = request.args.get('l_number')  # Retrieve l_number from URL parameters

    if request.method == 'POST':
        lab_location = request.form.get('lab_location')
        class_selected = request.form.get('class_selected')

        if not l_number:
            flash('L number is required!', 'danger')
            return redirect(url_for('landing'))

        sign_in_data = SignInData(
            l_number=l_number,
            lab_location=lab_location,
            class_selected=class_selected,
            sign_in_timestamp=datetime.now()
        )
        print("About to save data to DB...")
        db.session.add(sign_in_data)
        db.session.commit()
        print("Data saved to DB!")
        flash('Signed in successfully', 'success')
        return redirect(url_for('landing'))

    classes = request.args.getlist('classes')
    return render_template('sign_in.html', classes=classes)


@app.route('/sign-out', methods=['GET', 'POST'])
def sign_out():
    if request.method == 'POST':
        l_number = request.form.get('l_number')
        student = SignInData.query.filter_by(l_number=l_number).first()
        if student:
            student.sign_out_timestamp = datetime.now()
            student.comments = request.form.get('comments')
            db.session.commit()
            flash('Signed out successfully', 'success')
        else:
            flash('Student not found', 'danger')
    return render_template('sign_out.html')


@app.route('/query-login')
def query_login():
    data = SignInData.query.all()
    tsv_data = "L Number\tLab Location\tClass Selected\tSign-in Timestamp\tSign-out Timestamp\tComments\n"
    for entry in data:
        tsv_data += f"{entry.l_number}\t{entry.lab_location}\t{entry.class_selected}\t"
        tsv_data += f"{entry.sign_in_timestamp}\t{entry.sign_out_timestamp}\t{entry.comments}\n"
    return Response(tsv_data, mimetype='text/tab-separated-values')


@app.route('/query-selection')
def query_selection():
    # Placeholder: This route will have similar logic to the above but tailored for class selection data
    return "Placeholder for class selection data in TSV format"


@app.route('/check-db')
def check_db():
    db.session.commit()  # Explicitly commit the session
    data = SignInData.query.all()
    for entry in data:
        print(entry.l_number, entry.lab_location, entry.class_selected)
    return "Checked DB. See console for output."


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)

# Project Title: Online Lab Attendance System

## Overview

This Flask-based web application provides a sophisticated platform for managing lab attendance in educational institutions. It features robust functionalities including user sign-in/out, authentication, data management, IP mapping, message setting, and comprehensive admin controls. The system is adept at secure data processing, encryption, emailing, and offers a detailed logging mechanism.

## Key Features

- Student sign-in/out with lab session tracking.
- Admin dashboard for user and data management.
- IP mapping for lab locations.
- Secure messaging system for lab announcements.
- Extensive error handling and data encryption.
- Email functionalities for query and notifications.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.x
- Flask
- Pip (Python package installer)
- Virtual environment (recommended)
- SQLite/PostgreSQL

### Installation

To set up the project:

1. Clone the repository:
   ```sh
   git clone <repository-url>
   ```

2. Navigate to the project directory:
   ```sh
   cd online-lab-attendance-system
   ```

3. Set up a virtual environment and activate it:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scriptsctivate`
   ```

4. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

5. Initialize and migrate the database:
   ```sh
   flask db init
   flask db migrate
   flask db upgrade
   ```

6. Run the Flask server:
   ```sh
   flask run
   ```

## Project Structure

### Backend

- `main.py`: Core application setup, routes, and logic.
- `models.py`: Database models for users, sign-in data, IP locations, messages, and logs.
- `admin.py`: Administrative functionalities and backend logic.

### Frontend

- `templates`: HTML templates for UI rendering.
- `static`: CSS and JavaScript files for styling and interactive features.

### Main Functionalities

- **User Authentication**: Secure login/logout for students and administrators.
- **Attendance Tracking**: Students can sign in/out of labs, with their attendance time recorded.
- **Admin Dashboard**: Administrators can manage users, IP mappings, messages, and view logs.
- **Data Management**: Query and download attendance data, manage term dates, and send emails.
- **Message Board**: Administrators can post messages for specific lab locations.
- **IP Mapping**: Associate lab locations with specific IP addresses for accurate tracking.

## Configurations

The application's configuration, including database setup, SMTP settings, and encryption keys, is managed through `config.toml`.

## Technologies Used

- Flask: Python web framework.
- SQLAlchemy: ORM for database interactions.
- SQLite/PostgreSQL: Database systems.
- Jinja2: Templating engine.
- WTForms: Form handling.
- Cryptography: Secure token handling and encryption.

## Dependencies

Listed in `requirements.txt`, including Flask extensions like Flask-Login, Flask-WTF, Flask-SQLAlchemy, and others for security and functionality.

## Third-Party Libraries

- Flask-Login: User session management.
- Flask-WTF: Forms and CSRF protection.
- Cryptography: Encryption and secure token management.
- msmtp: Email client for sending notifications and queries.

## About the Project

Developed by LCC-CIT-Lab, this project aims to streamline lab attendance management and ensure secure and efficient operations within educational settings. The system is open-source and welcomes contributions and feedback.

## Contact

- GitHub: @LCC-CIT-Lab
- Email: CITLab@lanecc.edu

## Additional Features and To-Dos

### Upcoming Features

- More detailed statistics on lab usage (`more_statistics.html`).
- Gamification elements for student engagement (`gamification.html`).
- Instructor module for class and attendance management (`instructor.html`).

### To-Dos

- CSV file upload for term date management in `term_management.html`.
- Verify log deletion and auto sign-out.
- Implement logout form as a Flask-WTForms component.

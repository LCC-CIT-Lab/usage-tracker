# Project Title: Online Lab Attendance System

## Overview

The Online Lab Attendance System is a Flask-based web application designed for managing lab attendance in educational institutions. It automates the process of student sign-ins/outs and provides administrators with robust tools for user and data management. The application integrates secure authentication, IP mapping, a messaging system, and various administrative functionalities.

## Key Features

- Student Sign-In/Out: Tracks student attendance with lab session logging.
- Admin Dashboard: Manages users, IP mappings, term dates, messages, and data queries.
- IP Mapping: Associates lab locations with IP addresses for accurate tracking.
- Messaging System: Allows admins to post lab-specific announcements.
- Data Management: Queries and downloads attendance data; handles manual sign-in settings.
- Automatic Student Sign-Out: Signs out students automatically at a specified time.
- Feedback System: Users can send feedback or report issues via email.
- QR Code Generation: Creates QR codes for easy lab location access.
- Secure Logging: Maintains detailed logs of application activities.

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
- msmtp: Email client for sending notifications and queries.
- Paramiko: SSH interaction for file access.

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



# Project Title: Online Lab Attendance System

## Overview

This Flask-based web application serves as a comprehensive system for tracking lab attendance, providing functionalities for user sign-in and sign-out, user authentication, data management, and administrative features. The system is designed to handle secure data processing, messaging, encryption, and email functionalities within an educational setting.

## Getting Started

These instructions will guide you through setting up the project locally for development and testing purposes.

### Prerequisites

- Python 3.x
- Flask
- Pip (Python package installer)
- Virtual environment (recommended)

### Installation

Follow these steps to set up your project:

1. Clone the repository:
   ```sh
   git clone <repository-url>
   ```

2. Navigate to the project directory:
   ```sh
   cd yourproject
   ```

3. Set up a virtual environment and activate it:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

4. Install the required dependencies:
   ```sh
   pip install -r requirements.txt
   ```

5. Initialize the database:
   ```sh
   flask db upgrade
   ```

6. Run the server:
   ```sh
   flask run
   ```

## Project Structure

### app.py

Handles the user interface logic, data processing, messaging, encryption, and email functionalities.

### Routes

- **Landing**: The entry point where students enter their L number to sign in or sign out.
- **Sign-in**: Allows students to sign in for a session by selecting their lab location and class.
- **Sign-out**: Enables students to sign out and submit optional comments.
- **Query Login**: A secure access point for querying attendance data via authorized email addresses.
- **Query Selection**: Allows extraction and viewing of class data within selected date ranges.
- **Query Error**: Displays errors related to login or data selection.

### Templates

Contains HTML templates for rendering the web interface, including sign-in/out forms, admin dashboard, user management, and error pages.


## Configurations

Configurations are managed through `config.toml`, which includes database setup, SMTP settings, and application secrets.

## Technologies

- Flask for the web framework.
- SQLAlchemy for database interactions.
- SQLite/PostgreSQL as the database system.
- Jinja2 for templating.
- WTForms for form handling.

## Dependencies

Dependencies are listed in the `requirements.txt` file and include third-party libraries such as Flask-Login, Flask-WTF, and Cryptography.

## Third Party Libraries

- Flask-Login: User session management.
- Flask-WTF: Form handling and validation.
- Cryptography: Encryption for secure token handling.
- msmtp: - Client for sending e-mail

## About

Lab Attendance Website is an initiative by LCC-CIT-Lab to provide a secure and straightforward way for users to log-in to labs around campus. The project is open for contributions and welcomes feedback.

## Contact

- GitHub: @LCC-CIT-Lab
- Email: CITLab@lanecc.edu

## Additional Details

### Database

The application uses SQLite with SQLAlchemy. It includes tables for SignInData and User Management.

### Error Handling

Comprehensive error handling is in place for scenarios such as missing L numbers, database errors, failed logins, encryption issues, and email sending failures.

### Email Configuration

SMTP settings are configured through `config.toml`, and utility functions for sending emails are provided.

### Encryption

Fernet encryption is used for token generation and validation, with tokens expiring daily.

## To Do

- Implement IP address-based building selection.
- Further error handling improvements.
- Additional user management features.

"""
# Spec Sheet: Online Lab Attendance Form

## Framework:
- Flask

## Component:
- **app.py**: Handles the UI logic, data processing, messaging, encryption, and email functionalities.

## Routes:

### 1. Landing:
    - **Purpose**: Entry point to the application.
    - **Features**:
        - Form to enter the student's L number.
        - Submit button.
    - **Logic**:
        - Upon submission, validate the L number (length, number range).
        - If the student is already signed in for the current day and hasn't signed out, automatically sign them out.
        - Otherwise, redirect to the Sign-in page.
  
### 2. Sign-in:
    - **Purpose**: Allow students to sign in for a session.
    - **Features**:
        - Dropdown to select the lab location.
        - Dropdown to select the student's class.
        - Submit button.
    - **Options**:
        - Lab Location: CIT Lab, Other.
        - Student Classes: (Populated from the student's current classes).
    - **Logic**:
        - Return list of the student's current classes.
        - Save the sign-in data to an SQLite database using SQLAlchemy.
        - If student is already signed in on the same day without a sign-out, sign them out.

### 3. Sign-out:
    - **Purpose**: Allow students to sign out from a session.
    - **Features**:
        - Display message indicating the student is now signed out.
        - Optional comment section with submit button.
    - **Logic**:
        - If the user is already signed in, automatically select this page.
        - Upon landing, log the user out and save any comments to the database if submit is pressed.

### 4. Query Login:
    - **Purpose**: Secure access point for querying attendance data.
    - **Features**:
        - Form to enter an authorized email address.
        - Submit button.
    - **Logic**:
        - Validates if the email is authorized.
        - Generates a one-time valid token link and sends it to the email.
        - The token is valid until midnight of the same day.

### 5. Query Selection:
    - **Purpose**: Extract and view selected class data.
    - **Features**:
        - Form to select date range.
        - Two buttons to enter in current term and to submit.
    - **Logic**:
        - Fetches the attendance data for the specified date range from the SQLite database.
        - Sends the fetched data in CSV format to the user's email.

### 6. Query Error:
    - **Purpose**: Show error page if login or date range is incorrect.
    - **Features**:
        - State the error
    - **Logic**:
        - State the error on the login or selection page?

---

## Database:
- **Type**: SQLite
- **Tool**: SQLAlchemy
- **Tables**:
    - **SignInData**:
        - L number (Primary key)
        - Lab Location
        - Class Selected
        - Sign-in Timestamp
        - Sign-out Timestamp
        - Comments

---

## Additional Details:

### 1. SSHfs Configuration:
    - Define how the SSHfs connection is established.
    - Specify the location and format of the TSV file used for validation.
        - 

### 2. Error Handling:
    - Handle scenarios where the L number is not found.
    - Handle failed database writes/reads.
    - Manage unsuccessful logins.
    - Handle decryption errors and token validation issues.
    - Manage failed email sending operations.

### 3. Email Configuration:
    - Configured using SMTP settings from `config.toml`.
    - Utility functions for sending emails are integrated, such as sending comments and sending query access links.

### 4. Encryption:
    - A token generation and validation system has been set up using Fernet encryption.
    - Tokens are generated using a combination of the user's email and the current date, ensuring daily expiry.

## To Do:

### 1. Building selection by IP address.
"""

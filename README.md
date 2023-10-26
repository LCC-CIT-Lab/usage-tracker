
# Website Spec Sheet: Online Lab Attendance Form

## Framework:
- Flask

## Component:
- **app.py**: Handles the UI logic, data processing, and messaging.

## Routes:

### 1. Landing:
    - **Purpose**: Entry point to the application.
    - **Features**:
        - Form to enter the student's L number.
        - Submit button.
    - **Logic**:
        - Upon submission, use SSHfs to login to a server and then parse a TSV file.
        - Validate the L number (length, number range).
        - If the student is already signed in, redirect to the Sign-out page.
  
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

### 3. Sign-out:
    - **Purpose**: Allow students to sign out from a session.
    - **Features**:
        - Display message indicating the student is now signed out.
        - Optional comment section with submit button.
    - **Logic**:
        - If the user is already signed in, automatically select this page.
        - Upon landing, log the user out and save any comments to the database if submit is pressed.
  
### 4. Query Login:
    - **Purpose**: Extract and view login data.
    - **Features**:
        - Login form.
    - **Logic**:
        - After successful login, redirect to Query Selection page.
  
### 5. Query Selection:
    - **Purpose**: Extract and view selected class data.
    - **Features**:
        - Form to select date range.
        - Two buttons to enter in current term and to submit.
    - **Logic**:
        - Display the SQLite attendance data in CSV format.

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

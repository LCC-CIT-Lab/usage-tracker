
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
        - Upon submission, use SSHfs to parse a TSV file on the server.
        - Validate the L number.
        - Return validation status and list of the student's current classes.
  
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
        - Save the sign-in data to an SQLite database using SQLAlchemy.
        - If the student is already signed in, redirect to the Sign-out page.

### 3. Sign-out:
    - **Purpose**: Allow students to sign out from a session.
    - **Features**:
        - Display message indicating the student is signed in.
        - Optional comment section.
        - Sign-out button.
    - **Logic**:
        - If the user is already signed in, automatically select this page.
        - Upon clicking the sign-out button, log the user out and save any comments to the database.
  
### 4. Query Login:
    - **Purpose**: Extract and view login data.
    - **Features**:
        - Login form.
    - **Logic**:
        - After successful login, display the SQLite data in TSV format.
  
### 5. Query Selection:
    - **Purpose**: Extract and view selected class data.
    - **Features**:
        - Login form.
    - **Logic**:
        - After successful login, display the SQLite class selection data in TSV format.

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

### 2. Error Handling:
    - Handle scenarios where the L number is not found.
    - Handle failed database writes/reads.
    - Manage unsuccessful logins.

### 3. Security:
    - Ensure secure data transfer and storage.
    - Implement protection against SQL injection.
    - Ensure the security of the SSHfs connection.

### 4. UI/UX:
    - Design considerations for the app.
    - Mobile responsiveness.
    - Usability considerations.

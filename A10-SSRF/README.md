# Broken Authentication (A07) Lab

## Introduction

This is a Capture The Flag (CTF) challenge designed to help you understand and practice exploiting Broken Authentication vulnerabilities, which is one of the OWASP Top 10 security risks. The lab provides a hands-on environment where you can learn about authentication mechanisms and their potential weaknesses.

## Project Structure

```
FailureAuth-lab/
├── app.py              # Main application logic with authentication vulnerabilities
├── run.py              # Application entry point
├── init_db.py          # Database initialization script
├── data.db             # SQLite database
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker configuration
├── static/             # Static assets (CSS, JS, images)
├── templates/          # HTML templates
└── desgined/           # Design assets
```

## Prerequisites

- Python 3.6 or higher
- Docker (optional, for containerized deployment)
- Basic understanding of web applications and HTTP

## Dependencies

The project uses the following main dependencies:
- Flask v2.0.1 - Web framework
- Flask-SQLAlchemy v2.5.1 - SQL ORM
- Werkzeug v2.0.1 - WSGI utility library
- SQLAlchemy v1.4.23 - Database toolkit
- Gunicorn v21.2.0 - WSGI HTTP Server

## Installation and Setup

### Option 1: Local Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd FailureAuth-lab
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Unix or MacOS
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python init_db.py
```

5. Run the application:
```bash
python run.py
```

6. Access the application at `http://localhost:5000`

### Option 2: Docker Deployment

1. Build the Docker image:
```bash
docker build -t failureauth-lab .
```

2. Run the container:
```bash
docker run -p 5000:5000 failureauth-lab
```

3. Access the application at `http://localhost:5000`

## Challenge Details

### Objective
Your mission is to exploit weaknesses in the authentication system to gain administrative access to the application. Once you achieve admin access, you can retrieve the flag from the admin page.

### Vulnerabilities to Explore
The application contains two key authentication vulnerabilities:

1. **Username Enumeration**: The application provides different responses when attempting to register with an existing username
2. **Flawed Account Lockout Mechanism**: The application has a flawed implementation of account lockout functionality

### Difficulty Level
- **Medium** - Suitable for beginners to intermediate users learning about web application security
- Estimated completion time: 30-60 minutes

### Test Accounts
The following accounts are pre-configured for testing:

| Role  | Username | Password  |
|-------|----------|-----------|
| Admin | admin    | admin123  |
| User  | guest    | guestpass |

**Note:** It's recommended to create your own account for the challenge.

## Challenge Steps

1. Create a new user account or use a provided test account
2. Explore the authentication mechanisms (login and registration)
3. Identify the username enumeration vulnerability during registration
4. Understand how the account lockout mechanism works
5. Find the flaw in the account lockout implementation
6. Exploit the vulnerability to brute force an admin account
7. Access the admin area and retrieve the flag

## Hints

1. Pay attention to how the application responds when you attempt to register with an existing username
2. Observe how the system behaves after multiple failed login attempts
3. Test what happens when you successfully log in after failed attempts
4. Try to determine if successful logins reset the failed login counter
5. A fuzzing or brute force tool might help with this challenge (but use caution not to trigger actual security measures)

## Learning Resources

### Official Documentation
- [OWASP Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

### Additional Resources
- [PortSwigger Web Security Academy - Authentication](https://portswigger.net/web-security/authentication)
- [OWASP Testing Guide - Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

## Troubleshooting

If you encounter any issues:
1. Ensure all dependencies are correctly installed
2. Check if the database is properly initialized
3. Verify the application is running on the correct port
4. Clear your browser cache if you experience unexpected behavior

## Contributing

Feel free to submit issues and enhancement requests. Contributions are welcome!

## License

This project is created for educational purposes. Feel free to use and modify for learning about web application security.

## Credits

This lab was developed as an educational resource for learning about web application security, with a specific focus on Broken Authentication vulnerabilities. 
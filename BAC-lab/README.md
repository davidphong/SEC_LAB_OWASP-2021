# Broken Access Control (BAC) Lab

## Introduction

This is a Capture The Flag (CTF) challenge designed to help you understand and practice exploiting Broken Access Control vulnerabilities, which is one of the OWASP API Top 10 security risks. The lab provides a hands-on environment where you can learn about access control mechanisms and their potential weaknesses.

## Project Structure

```
BAC-lab/
├── app.py              # Main application logic
├── run.py             # Application entry point
├── init_db.py         # Database initialization script
├── data.db            # SQLite database
├── requirements.txt   # Python dependencies
├── Dockerfile         # Docker configuration
├── static/           # Static assets (CSS, JS, images)
├── templates/        # HTML templates
└── desgined/        # Design assets
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
cd BAC-lab
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
docker build -t bac-lab .
```

2. Run the container:
```bash
docker run -p 5000:5000 bac-lab
```

3. Access the application at `http://localhost:5000`

## Challenge Details

### Objective
Your mission is to exploit a vulnerability in the profile update functionality to escalate your privileges from a regular user to an administrator. Once you achieve admin access, you can retrieve the flag from the admin page.

### Difficulty Level
- **Easy** - Suitable for beginners in web application security
- Estimated completion time: 30-60 minutes

### Test Accounts
The following accounts are pre-configured for testing:

| Role  | Username | Password  |
|-------|----------|-----------|
| Admin | admin    | adminpass |
| User  | guest    | guestpass |

**Note:** It's recommended to create your own account for the challenge.

## Challenge Steps

1. Register a new user account
2. Log in with your credentials
3. Navigate to your profile page
4. Analyze the profile update functionality
5. Find and exploit the access control vulnerability
6. Access the admin area
7. Retrieve the flag

## Hints

1. Pay attention to the data being sent during profile updates
2. Use browser developer tools (F12) to inspect and modify network requests
3. Look for ways to manipulate user role or privilege information
4. Think about what fields might be missing from the frontend but processed by the backend

## Learning Resources

### Official Documentation
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP API Security Top 10 - Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

### Additional Resources
- [PortSwigger Web Security Academy - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [OWASP Testing Guide - Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

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

This lab was developed as an educational resource for learning about web application security, with a specific focus on Broken Access Control vulnerabilities. 
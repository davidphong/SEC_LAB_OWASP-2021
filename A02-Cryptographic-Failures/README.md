# Cryptographic Failures (A02) Lab

## Introduction

This is a Capture The Flag (CTF) challenge designed to help you understand and practice exploiting Cryptographic Failures vulnerabilities, which is one of the OWASP Top 10 security risks. The lab provides a hands-on environment where you can learn about insecure cryptographic implementations, weak hashing algorithms, and exposed credentials in backup files.

## Project Structure

```
A02-Cryptographic-Failures/
├── app.py              # Main application logic with cryptographic vulnerabilities
├── data.db             # SQLite database
├── requirements.txt    # Python dependencies
├── static/             # Static assets (CSS, JS, images, and hidden backup files)
├── templates/          # HTML templates
└── desgined/           # Design assets
```

## Prerequisites

- Python 3.6 or higher
- Docker (optional, for containerized deployment)
- Basic understanding of web applications and cryptography

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
cd A02-Cryptographic-Failures
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

4. Run the application:
```bash
python app.py
```

5. Access the application at `http://localhost:5000`

### Option 2: Docker Deployment

1. Build the Docker image:
```bash
docker build -t crypto-failures-lab .
```

2. Run the container:
```bash
docker run -p 5000:5000 crypto-failures-lab
```

3. Access the application at `http://localhost:5000`

## Challenge Details

### Objective
Your mission is to discover and exploit cryptographic weaknesses in the application to gain administrative access. The application contains a hidden backup file with insecurely hashed credentials that you need to find and crack.

### Vulnerabilities to Explore
The application contains two key cryptographic vulnerabilities:

1. **Weak Hashing Algorithm**: The application uses a weak hashing algorithm (MD5) for a database backup file
2. **Exposed Credentials**: A database backup file containing hashed credentials is stored in a publicly accessible location

### Difficulty Level
- **Medium** - Suitable for beginners to intermediate users learning about web application security
- Estimated completion time: 30-60 minutes

### Test Accounts
The following accounts are pre-configured for testing:

| Role  | Username | Password  |
|-------|----------|-----------|
| Admin | admin    | admin123  |
| User  | guest    | guestpass |

**Note:** Your goal is to find the admin password without using the provided credentials.

## Challenge Steps

1. Explore the website and understand its structure
2. Discover the hidden backup file by scanning for common backup extensions
3. Analyze the backup file to find the hashed credentials
4. Identify the weak hashing algorithm used
5. Crack the hash to recover the admin password
6. Log in as admin and retrieve the flag

## Hints

1. Web servers often have hidden files that aren't linked from the main site
2. Look for files with extensions like .bak, .backup, .old, .txt, .log
3. Directory scanning tools like dirsearch or gobuster can help find hidden files
4. MD5 is a cryptographically weak algorithm and can be easily cracked
5. The admin password might be referenced in comments or notes within the backup file

## Learning Resources

### Official Documentation
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Additional Resources
- [PortSwigger Web Security Academy - Weak Cryptography](https://portswigger.net/web-security/crypto)
- [OWASP Testing Guide - Testing for Weak Cryptography](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)

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

This lab was developed as an educational resource for learning about web application security, with a specific focus on Cryptographic Failures vulnerabilities. 
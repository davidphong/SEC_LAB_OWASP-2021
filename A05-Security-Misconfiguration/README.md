# Path Traversal (A05) Lab

## Introduction

This is a Capture The Flag (CTF) challenge designed to help you understand and practice exploiting Path Traversal vulnerabilities, which falls under the Security Misconfiguration category in the OWASP Top 10 security risks. The lab provides a hands-on environment where you can learn about path traversal attacks and their potential impact.

## Project Structure

```
PathTraversal-lab/
├── app.py              # Main application logic with path traversal vulnerability
├── run.py              # Application entry point
├── init_db.py          # Database initialization script
├── data.db             # SQLite database
├── flag.txt            # Secret flag file
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker configuration
├── static/             # Static assets (CSS, JS, images)
└── templates/          # HTML templates
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

## Installation and Setup

### Option 1: Local Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd PathTraversal-lab
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
docker build -t pathtraversal-lab .
```

2. Run the container:
```bash
docker run -p 5000:5000 pathtraversal-lab
```

3. Access the application at `http://localhost:5000`

## Challenge Details

### Objective
Your mission is to exploit a path traversal vulnerability in the blog image loading functionality to access sensitive files on the server. The flag is stored in a file called `flag.txt` in the application's root directory.

### Vulnerability to Explore
The application contains a path traversal vulnerability in the image loading endpoint, which allows attackers to access files outside the intended directory.

### Difficulty Level
- **Medium** - Suitable for beginners to intermediate users learning about web application security
- Estimated completion time: 15-30 minutes

### Test Accounts
The following accounts are pre-configured for testing:

| Role  | Username | Password  |
|-------|----------|-----------|
| Admin | admin    | admin123  |
| User  | guest    | guestpass |

## Challenge Steps

1. Log in to the application using one of the provided test accounts
2. Browse the blog section and observe how images are loaded
3. Identify the endpoint responsible for serving images
4. Analyze the URL pattern used for loading images
5. Craft a path traversal payload to access files outside the intended directory
6. Access the flag.txt file in the application's root directory

## Hints

1. Pay attention to the URL structure when viewing blog posts with images
2. Try manipulating the image path parameter to navigate to different directories
3. Common path traversal patterns include `../` sequences to move up directories
4. Remember that you need to access the `flag.txt` file in the root directory

## Learning Resources

### Official Documentation
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

### Additional Resources
- [PortSwigger Web Security Academy - Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP Testing Guide - Path Traversal Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)

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

This lab was developed as an educational resource for learning about web application security, with a specific focus on Path Traversal vulnerabilities. 
# SSRF Challenge

## Description
This challenge simulates a vulnerable web application with a Server-Side Request Forgery (SSRF) vulnerability. The application allows users to download files from the internet by providing a URL. However, the URL validation is insufficient, allowing attackers to access internal services and resources.

## Learning Objective
- Understand how SSRF vulnerabilities work
- Learn how to identify and exploit SSRF vulnerabilities
- Understand the potential impact of SSRF on internal services
- Learn best practices for preventing SSRF attacks

## Setup Instructions

### Using Docker (Recommended)
1. Make sure you have Docker and Docker Compose installed
2. Navigate to the challenge directory:
   ```
   cd A10-SSRF
   ```
3. Build and run the Docker container:
   ```
   docker-compose up --build
   ```
4. Access the application at http://localhost:5001

### Manual Setup
1. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```
2. Run the application:
   ```
   python run.py
   ```
3. Access the application at http://localhost:5001

## Challenge Overview
The "File Downloader Tool" web application allows users to enter a URL, and the application will download the content from that URL. The application has a vulnerability that allows accessing internal services.

To complete the challenge, you need to:
1. Identify the SSRF vulnerability in the web application
2. Exploit the vulnerability to access an internal service
3. Retrieve the flag from the internal service

Good luck!

## Files Included
- `app.py` - Main application code
- `run.py` - Script to run the application
- `requirements.txt` - Python dependencies
- `templates/` - HTML templates for the web interface
- `static/` - CSS and other static files
- `Dockerfile` and `docker-compose.yml` - Docker configuration
- `solution.md` - (Hidden) Contains the solution to the challenge

## References
- [OWASP - Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [HackTricks - SSRF (Server Side Request Forgery)](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery) 
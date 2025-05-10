# Broken Access Control (BAC) Lab

This is a CTF (Capture The Flag) challenge focusing on Broken Access Control, one of the OWASP API Top 10 vulnerabilities.

## Overview

In this lab, you'll need to exploit a vulnerability in the profile update functionality to escalate your privileges from a regular user to an administrator. Once you have admin access, you can retrieve the flag from the admin page.

## Challenge Description

You discovered a web application with a user profile feature. Your goal is to find and exploit a security vulnerability to gain administrative access to the system and retrieve the flag.

## Setup Instructions

### Option 1: Run with Docker

1. Make sure you have Docker installed
2. Build and run the Docker container:

```bash
cd BAC-lab
docker build -t bac-lab .
docker run -p 5000:5000 bac-lab
```

3. Access the application at `http://localhost:5000`

### Option 2: Run Locally

1. Make sure you have Python 3.6+ installed
2. Install the required packages:

```bash
cd BAC-lab
pip install -r requirements.txt
```

3. Run the application:

```bash
python run.py
```

4. Access the application at `http://localhost:5000`

## Getting Started

1. Register a new user account
2. Log in with your credentials
3. Explore the application, especially the profile page
4. Find and exploit the vulnerability to gain admin access
5. Find the flag in the admin area

## Default Accounts

For testing purposes, these accounts are pre-configured:

- Admin: username `admin` / password `adminpass`
- User: username `guest` / password `guestpass`

However, it's recommended to create your own account for the challenge.

## Challenge Difficulty

This challenge is rated as **Easy** and is suitable for beginners learning about web application security and Broken Access Control vulnerabilities.

## Learning Resources

If you're stuck, here are some resources to learn more about Broken Access Control:

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP API Security Top 10 - Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger Web Security Academy - Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)

## Credits

This lab was created as a practice environment for learning about web application security, particularly focusing on Broken Access Control vulnerabilities.

## Hints

1. Look at what data is being sent when you update your profile
2. Try to modify this data to include additional fields
3. You'll need to use browser developer tools to see and modify network requests 
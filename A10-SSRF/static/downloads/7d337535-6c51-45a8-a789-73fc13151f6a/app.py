from flask import Flask, render_template, request, redirect, url_for, send_file, abort, session
import os
import requests
import socket
from urllib.parse import urlparse
import time
import uuid
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "VNPT_CTF_SSRF_Challenge_Secret_Key"

# Database setup
DATABASE = 'data.db'

# Directory for downloaded files
DOWNLOADS_DIR = os.path.join("static", "downloads")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0
    )
    ''')
    
    # Create admin user
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_password = generate_password_hash("super_secure_admin_password")
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                      ("admin", admin_password, True))
    
    conn.commit()
    conn.close()

# Validate URL - Vulnerable to SSRF
def validate_url(url):
    parsed_url = urlparse(url)
    
    # Basic validation only - VULNERABLE TO SSRF
    if not parsed_url.scheme or not parsed_url.netloc:
        return False
    
    # No proper validation for internal IPs - VULNERABLE
    return True

@app.before_request
def assign_session():
    # Assign a session ID if not already assigned
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())

@app.route("/")
def index():
    return redirect(url_for("downloader"))

@app.route("/downloader")
def downloader():
    return render_template("index.html")

@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "").strip()
    
    # Minimal URL validation - VULNERABLE TO SSRF
    if not validate_url(url):
        return render_template("error.html", message="Invalid URL format!")
    
    try:
        # No restrictions on URL - VULNERABLE TO SSRF
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return render_template("error.html", message="Failed to download file!")

        # Save file to user's session directory
        user_dir = os.path.join(DOWNLOADS_DIR, session["session_id"])
        os.makedirs(user_dir, exist_ok=True)
        
        # Get filename from URL or use default
        file_name = os.path.basename(urlparse(url).path) or "downloaded_file"
        file_path = os.path.join(user_dir, file_name)
        
        with open(file_path, "wb") as f:
            f.write(response.content)
            
        return render_template("result.html", file_name=file_name)
        
    except Exception as e:
        return render_template("error.html", message=f"Error fetching URL: {str(e)}")

@app.route("/download/<file_name>")
def download(file_name):
    user_dir = os.path.join(DOWNLOADS_DIR, session["session_id"])
    file_path = os.path.join(user_dir, file_name)
    
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        abort(404)

@app.route("/blog")
def blog():
    return render_template("error.html", message="Blog section coming soon!")

@app.route("/profile")
def profile():
    return render_template("error.html", message="Profile section coming soon!")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)

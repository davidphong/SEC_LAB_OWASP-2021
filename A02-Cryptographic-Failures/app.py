"""
Flask app for Cryptographic Failures Challenge.

⚠️  This app demonstrates OWASP A02:2021 - Cryptographic Failures
    1. Weak hash algorithm for password storage
    2. Database backup with exposed credentials
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   session, g, abort, jsonify, flash)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os
import time
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.update(
    SECRET_KEY='dev',
    SQLALCHEMY_DATABASE_URI='sqlite:///data.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

db = SQLAlchemy(app)

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default="user")  # user / admin
    
    # Additional user profile fields
    full_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(50))
    country = db.Column(db.String(50))
    bio = db.Column(db.Text)
    company = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    website = db.Column(db.String(100))
    social_media = db.Column(db.String(100))

    # ---------- helpers ----------
    def set_pw(self, pw):
        # Using secure hash for normal operations
        self.password = generate_password_hash(pw)

    def chk_pw(self, pw):
        return check_password_hash(self.password, pw)

# Blog post model
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(200))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50))
    summary = db.Column(db.String(300))
    
    def __repr__(self):
        return f'<BlogPost {self.title}>'

# ---------------- Middleware: load user from session ----------------
@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        g.user = User.query.get(session["uid"])

# ---------------- Homepage ----------------
@app.route("/")
def index():
    # Get latest blog posts for homepage
    latest_posts = BlogPost.query.order_by(BlogPost.created_at.desc()).limit(3).all()
    return render_template("index.html", latest_posts=latest_posts)

# ---------------- Registration ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Check if username already exists
        existing_user = User.query.filter_by(username=request.form["username"]).first()
        if existing_user:
            flash("Username already exists! Please choose a different username.", "danger")
            return render_template("register.html")
        
        try:
            u = User(
                username=request.form["username"],
                email=request.form["email"],
            )
            u.set_pw(request.form["password"])
            db.session.add(u)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {e}")
            flash(f"Error during registration: {str(e)}", "danger")
    return render_template("register.html")

# ---------------- Login ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        
        # Find user in database
        u = User.query.filter_by(username=username).first()
        
        # Check username and password
        if u and u.chk_pw(request.form["password"]):
            session.clear()
            session["uid"] = u.id
            session["role"] = u.role
            flash(f"Welcome back, {u.username}!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password!", "danger")
    
    return render_template("login.html")

# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

# ---------------- User Profile ----------------
@app.route("/profile")
def profile():
    if g.user is None:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template("profile.html")

# ---------------- API Update User ----------------
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    """
    *Permissions*:
        - Only the account owner can edit.
    """
    if g.user is None or g.user.id != uid:
        abort(403)

    data = request.get_json(force=True)
    print(f"Update user data received: {data}")

    # List of fields that can be edited
    allowed_fields = [
        "email", "full_name", "phone_number", "address", 
        "city", "country", "bio", "company", "job_title", 
        "website", "social_media"
    ]
    
    # Only update allowed fields
    for k, v in data.items():
        if k in allowed_fields:
            setattr(g.user, k, v)

    try:
        db.session.commit()
        return jsonify(msg="Profile updated successfully")
    except Exception as e:
        db.session.rollback()
        print(f"Error updating profile: {e}")
        return jsonify(error=f"Error: {str(e)}"), 400

# ---------------- Admin Page ----------------
@app.route("/admin")
def admin():
    if not g.user:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    if g.user.role != "admin":  # Check directly from user data, not session
        flash("Access denied! Admin privileges required.", "danger")
        abort(403)
    flag = "VNPT{Weak_Hashing_Algorithm_Leads_To_Password_Compromise}"
    return render_template("admin.html", flag=flag)

# ---------------- Blog Routes ----------------
# List all blog posts
@app.route("/blog")
def blog_list():
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).all()
    return render_template("blog_list.html", posts=posts)

# View single blog post
@app.route("/blog/<int:post_id>")
def blog_detail(post_id):
    post = BlogPost.query.get_or_404(post_id)
    return render_template("blog_detail.html", post=post)

# Create new blog post (admin only)
@app.route("/blog/new", methods=["GET", "POST"])
def blog_new():
    if not g.user or g.user.role != "admin":
        flash("Only admins can create blog posts.", "danger")
        return redirect(url_for("blog_list"))
        
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        summary = request.form.get("summary")
        category = request.form.get("category")
        image_path = request.form.get("image_path", "desgined/des1.png")  # Default image
        
        new_post = BlogPost(
            title=title,
            content=content,
            summary=summary,
            category=category,
            image_path=image_path,
            author_id=g.user.id
        )
        
        db.session.add(new_post)
        db.session.commit()
        
        flash("Blog post created successfully!", "success")
        return redirect(url_for("blog_detail", post_id=new_post.id))
        
    return render_template("blog_new.html")

@app.route("/backup")
def backup_redirect():
    return redirect("/static/db_backup.bak")

# ---------------- Create database backup file with weak hashing ----------------
def create_db_backup():
    """Create a backup file with credentials using a weak hashing algorithm (MD5)"""
    backup_path = os.path.join(app.static_folder, 'db_backup.bak')
    with open(backup_path, 'w') as f:
        f.write("# Database Backup - CONFIDENTIAL\n")
        f.write("# Date: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("# User accounts (username, email, md5_password)\n\n")
        
        users = User.query.all()
        for user in users:
            # Use weak MD5 hashing for password backup - VULNERABLE!
            if user.username == "admin":
                # For admin, use actual MD5 hash of "admin@123"
                md5_hash = hashlib.md5("admin@123".encode()).hexdigest()
                f.write(f"{user.username},{user.email},{md5_hash}\n")
                # "accidentally" include the actual password in a comment
                # f.write(f"# Note: admin password hash needs to be updated to new format (current: admin@123)\n")
            else:
                # For other users, just use a dummy hash
                md5_hash = hashlib.md5(f"{user.username}_password".encode()).hexdigest()
                f.write(f"{user.username},{user.email},{md5_hash}\n")
                
        f.write("\n# End of backup\n")
    print(f"✓ Database backup created at {backup_path}")

# ---------------- Initialize DB ----------------
def init_db():
    with app.app_context():
        db.create_all()
        # Only create sample users if there are none
        if not User.query.first():
            admin = User(username="admin", email="admin@lab", role="admin")
            admin.set_pw("admin@123")  # Simple password for learning purposes
            user = User(username="guest", email="guest@lab")
            user.set_pw("guestpass")
            db.session.add_all([admin, user])
            db.session.commit()
            print("✓ Database seeded.")
            
            # Create sample blog posts
            blog_posts = [
                {
                    "title": "Best Practices for Secure Password Storage",
                    "content": """
                    <p>Password security is crucial for protecting user data. Here are some best practices for secure password storage:</p>

                    <h3>Use Strong Hashing Algorithms</h3>
                    <p>Always use modern hashing algorithms like bcrypt, Argon2, or PBKDF2 with sufficient iterations. Never use deprecated algorithms like MD5 or SHA1 for password storage.</p>

                    <h3>Implement Salting</h3>
                    <p>Always use unique salts for each password to prevent rainbow table attacks. The salt should be randomly generated and stored alongside the password hash.</p>

                    <h3>Key Stretching</h3>
                    <p>Use algorithms that support key stretching to make brute force attacks more computationally expensive.</p>

                    <h3>Secure Backup Practices</h3>
                    <p>Always encrypt database backups and never store them in publicly accessible locations. Treat backup files with the same level of security as your production database.</p>
                    """,
                    "summary": "A guide to secure password storage practices, including modern hashing algorithms, salting, and key stretching techniques to protect user credentials.",
                    "category": "Security",
                    "image_path": "desgined/des1.png",
                    "author_id": 1
                }
            ]
            
            for post_data in blog_posts:
                post = BlogPost(**post_data)
                db.session.add(post)
                
            db.session.commit()
            print("✓ Sample blog posts added.")
            
            # Create database backup with weak hashing
            create_db_backup()

if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('data.db'):
        init_db()
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=True) 
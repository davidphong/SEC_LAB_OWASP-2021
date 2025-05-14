"""
Flask app chính.

⚠️  Đây là file chứa lỗ hổng Broken Access Control.
    Route /api/user/<uid> **không** giới hạn các trường được phép sửa,
    nên client có thể nâng "role" = "admin".
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   session, g, abort, jsonify, flash)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os

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
        self.password = generate_password_hash(pw)

    def chk_pw(self, pw):
        return check_password_hash(self.password, pw)

# ---------------- Middleware: load user từ session ----------------
@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        g.user = User.query.get(session["uid"])

# ---------------- Trang chủ ----------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------------- Đăng ký ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        print(f"Register form submitted: {request.form}")
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

# ---------------- Đăng nhập ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        print(f"Login form submitted: {request.form}")
        u = User.query.filter_by(username=request.form["username"]).first()
        if u and u.chk_pw(request.form["password"]):
            session.clear()
            session["uid"] = u.id
            session["role"] = u.role
            flash(f"Welcome back, {u.username}!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password!", "danger")
    return render_template("login.html")

# ---------------- Đăng xuất ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

# ---------------- Hồ sơ người dùng ----------------
@app.route("/profile")
def profile():
    if g.user is None:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template("profile.html")

# ---------------- API UPDATE (VULNERABLE) ----------------
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    """
    *Quyền*:
        - Chỉ chủ tài khoản tự sửa.
    *Lỗ hổng*:
        - Không whitelist field => sửa được **role**.
    """
    if g.user is None or g.user.id != uid:
        abort(403)

    data = request.get_json(force=True)
    print(f"Update user data received: {data}")

    # ---------- VULN START ----------
    for k, v in data.items():          # <─ không kiểm soát
        setattr(g.user, k, v)          #     => client gửi "role":"admin"
    # ---------- VULN END ------------

    try:
        db.session.commit()
        session["role"] = g.user.role      # cập nhật session
        return jsonify(msg="Profile updated successfully")
    except Exception as e:
        db.session.rollback()
        print(f"Error updating profile: {e}")
        return jsonify(error=f"Error: {str(e)}"), 400

# ---------------- Trang Admin ----------------
@app.route("/admin")
def admin():
    if not g.user:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        flash("Access denied! Admin privileges required.", "danger")
        abort(403)
    flag = "VNPT{BCA_via_platform_misconfiguration}"
    return render_template("admin.html", flag=flag)

# ---------------- Initialize DB ----------------
def init_db():
    with app.app_context():
        db.create_all()
        # Chỉ tạo users mẫu nếu chưa có user nào
        if not User.query.first():
            admin = User(username="admin", email="admin@lab", role="admin")
            admin.set_pw("adminpass")
            user = User(username="guest", email="guest@lab")
            user.set_pw("guestpass")
            db.session.add_all([admin, user])
            db.session.commit()
            print("✓ Database seeded.")

if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('data.db'):
        init_db()
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=True)

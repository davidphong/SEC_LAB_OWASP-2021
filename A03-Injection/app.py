"""
Flask app chính.

⚠️  lỗ hổng Server Side Template Injection (SSTI):
    1. Render dữ liệu từ các trường bio của user không được sanitize
    2. Attacker có thể chèn template code vào trường bio để khai thác
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   session, g, abort, jsonify, flash, render_template_string)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os
import time
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.update(
    SECRET_KEY='dev',
    SQLALCHEMY_DATABASE_URI='sqlite:///data.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

db = SQLAlchemy(app)

# Dictionary để theo dõi số lần đăng nhập sai và thời gian khóa tài khoản
# Format: { username: {"attempts": count, "locked_until": timestamp} }
failed_login_attempts = {}

# Dictionary để theo dõi số lần đăng nhập sai và thời gian khóa theo IP
# Format: { ip_address: {"attempts": count, "locked_until": timestamp} }
failed_login_attempts_by_ip = {}

# ---------- Models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default="user")  # user / admin
    
    # User profile fields
    full_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(50))
    country = db.Column(db.String(50))
    bio = db.Column(db.Text)  # VULNERABLE: Bio field can contain SSTI payloads
    company = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    location = db.Column(db.String(100))
    website = db.Column(db.String(100))
    social_media = db.Column(db.String(100))

    # ---------- helpers ----------
    def set_pw(self, pw):
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

# ---------------- Middleware: load user từ session ----------------
@app.before_request
def load_user():
    g.user = None
    if "uid" in session:
        g.user = User.query.get(session["uid"])

# ---------------- Trang chủ ----------------
@app.route("/")
def index():
    # Get latest blog posts for homepage
    latest_posts = BlogPost.query.order_by(BlogPost.created_at.desc()).limit(3).all()
    return render_template("index.html", latest_posts=latest_posts)

# ---------------- Đăng ký ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        print(f"Register form submitted: {request.form}")
        
        # ---------- VULN #1: Username Enumeration ----------
        # Kiểm tra xem username đã tồn tại chưa và trả về thông báo cụ thể
        existing_user = User.query.filter_by(username=request.form["username"]).first()
        if existing_user:
            flash("Username already exists! Please choose a different username.", "danger")
            return render_template("register.html")
        # ---------- END VULN #1 ----------
        
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
        username = request.form["username"]
        ip_address = request.remote_addr
        
        # ---------- FIXED: Improved Account Lockout Mechanism by IP ----------
        # Kiểm tra xem IP có bị khóa hay không
        if ip_address in failed_login_attempts_by_ip:
            lock_info = failed_login_attempts_by_ip[ip_address]
            
            # Nếu IP bị khóa và thời gian khóa chưa hết
            if "locked_until" in lock_info and lock_info["locked_until"] > time.time():
                remaining_time = int(lock_info["locked_until"] - time.time())
                flash(f"Too many failed attempts from your IP. Try again in {remaining_time} seconds.", "danger")
                return render_template("login.html")
        
        # Tìm user trong database
        u = User.query.filter_by(username=username).first()
        
        # Kiểm tra username và password
        if u and u.chk_pw(request.form["password"]):
            # Đăng nhập thành công - reset số lần đăng nhập sai cho IP này
            if ip_address in failed_login_attempts_by_ip:
                del failed_login_attempts_by_ip[ip_address]
            
            session.clear()
            session["uid"] = u.id
            session["role"] = u.role
            flash(f"Welcome back, {u.username}!", "success")
            return redirect(url_for("index"))
        else:
            # Đăng nhập thất bại - tăng số lần đăng nhập sai theo IP
            if ip_address not in failed_login_attempts_by_ip:
                failed_login_attempts_by_ip[ip_address] = {"attempts": 1}
            else:
                # Tăng số lần đăng nhập sai
                failed_login_attempts_by_ip[ip_address]["attempts"] += 1
                
                # Nếu đăng nhập sai quá 3 lần, khóa IP trong 1 phút
                if failed_login_attempts_by_ip[ip_address]["attempts"] >= 3:
                    failed_login_attempts_by_ip[ip_address]["locked_until"] = time.time() + 60  # khóa 60 giây
                    flash("Too many failed login attempts. Your IP is locked for 1 minute.", "danger")
                    return render_template("login.html")
            
            flash("Invalid username or password!", "danger")
        # ---------- END FIX ----------
    
    return render_template("login.html")

# ---------------- Đăng xuất ----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

# ---------------- Hồ sơ người dùng ----------------
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if g.user is None:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
        
    if request.method == "POST":
        try:
            # Update user profile
            g.user.full_name = request.form.get("full_name")
            g.user.bio = request.form.get("bio")  # VULNERABLE: Bio can contain SSTI payload
            g.user.job_title = request.form.get("job_title")
            g.user.company = request.form.get("company")
            g.user.location = request.form.get("location")
            g.user.website = request.form.get("website")
            
            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for("view_profile_card"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating profile: {str(e)}", "danger")
    
    return render_template("profile.html")

# ---------------- Xem Profile Card ----------------
@app.route("/card")
def view_profile_card():
    """
    VULNERABLE: Renders bio field without sanitization
    """
    if g.user is None:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    
    # Create card HTML template
    card_html = f"""
    <div class="card">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0">Profile Card</h5>
        </div>
        <div class="card-body">
            <h4 class="card-title">{g.user.full_name or g.user.username}</h4>
            <h6 class="card-subtitle text-muted mb-3">{g.user.job_title} at {g.user.company}</h6>
            
            <!-- VULNERABLE: Direct rendering of bio field -->
            <div class="bio-section">
                <p class="card-text">{ g.user.bio }</p>
            </div>
            
            <p><i class="fas fa-map-marker-alt"></i> {g.user.location}</p>
            <p><i class="fas fa-globe"></i> <a href="{g.user.website}">{g.user.website}</a></p>
        </div>
    </div>
    """
    
    # VULNERABLE: Using render_template_string directly on user input
    try:
        rendered_card = render_template_string(card_html)
        return render_template("view_card.html", card=rendered_card)
    except Exception as e:
        flash(f"Error rendering profile card: {str(e)}", "danger")
        return redirect(url_for("profile"))

# ---------------- API UPDATE (FIXED: WHITELIST FIELDS) ----------------
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    """
    *Quyền*:
        - Chỉ chủ tài khoản tự sửa.
    *Sửa lỗi*:
        - Đã whitelist được các field cho phép sửa, không cho phép sửa role.
    """
    if g.user is None or g.user.id != uid:
        abort(403)

    data = request.get_json(force=True)
    print(f"Update user data received: {data}")

    # ---------- FIXED: WHITELIST FIELDS ----------
    # Danh sách các trường được phép sửa
    allowed_fields = [
        "email", "full_name", "phone_number", "address", 
        "city", "country", "bio", "company", "job_title", 
        "website", "social_media"
    ]
    
    # Chỉ cập nhật các trường được phép
    for k, v in data.items():
        if k in allowed_fields:  # Chỉ sửa các trường được whitelist
            setattr(g.user, k, v)
    # ---------- END FIX ----------

    try:
        db.session.commit()
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
    if g.user.role != "admin":  # Kiểm tra trực tiếp từ dữ liệu của user, không dùng session
        flash("Access denied! Admin privileges required.", "danger")
        abort(403)
    flag = "VNPT{SSTI_Flag_Not_Found}"
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

# ---------------- Initialize DB ----------------
def init_db():
    with app.app_context():
        db.create_all()
        # Chỉ tạo users mẫu nếu chưa có user nào
        if not User.query.first():
            admin = User(
                username="admin", 
                email="admin@lab", 
                role="admin",
                full_name="Administrator",
                bio="I am the administrator of this website",
                job_title="Admin",
                company="VNPT Security Lab",
                location="Vietnam",
                website="https://security.vnpt.vn"
            )
            admin.set_pw("admin123")
            
            user = User(
                username="guest", 
                email="guest@lab",
                full_name="Guest User",
                bio="I am a guest user",
                job_title="Guest",
                company="None",
                location="Unknown",
                website="https://example.com"
            )
            user.set_pw("guestpass")
            db.session.add_all([admin, user])
            db.session.commit()
            print("✓ Database seeded.")
            
            # Tạo file flag.txt
            with open("flag.txt", "w") as f:
                f.write("VNPT{SSTI_M4st3r_RCE_Achi3v3d!}")
            print("✓ Flag created.")
            
            # Add sample blog posts
            blog_posts = [
                {
                    "title": "Chiến dịch tấn công mạng có chủ đích APT nhắm vào các tổ chức chính trị",
                    "content": """
                    <p>Gần đây, các nhà nghiên cứu an ninh mạng đã phát hiện một chiến dịch tấn công mạng có chủ đích (APT) nhắm vào các tổ chức chính trị tại khu vực Đông Nam Á, đặc biệt là Việt Nam. Chiến dịch này sử dụng các kỹ thuật phức tạp và tinh vi để xâm nhập vào hệ thống mạng của các tổ chức.</p>

                    <h3>Phương thức tấn công</h3>
                    <p>Theo các chuyên gia an ninh mạng, nhóm tấn công đã sử dụng các email lừa đảo (phishing) được thiết kế cẩn thận, giả mạo các tổ chức uy tín hoặc đối tác thân thiết của nạn nhân. Các email này chứa các tệp đính kèm độc hại hoặc liên kết đến các trang web giả mạo để đánh cắp thông tin đăng nhập.</p>

                    <p>Sau khi xâm nhập thành công, nhóm tấn công đã sử dụng các công cụ và mã độc tiên tiến để duy trì quyền truy cập, thu thập thông tin và mở rộng phạm vi kiểm soát trong mạng nội bộ của tổ chức.</p>

                    <h3>Mục tiêu của nhóm tấn công</h3>
                    <p>Mục tiêu chính của nhóm tấn công là đánh cắp các thông tin nhạy cảm và tài liệu mật liên quan đến chính sách đối ngoại, quan hệ quốc tế và các quyết định chiến lược của các tổ chức bị nhắm tới. Những thông tin này có thể được sử dụng cho mục đích tình báo hoặc lợi ích chính trị.</p>

                    <h3>Khuyến nghị bảo mật</h3>
                    <p>Để bảo vệ khỏi các cuộc tấn công tương tự, các tổ chức nên:</p>
                    <ul>
                        <li>Tăng cường đào tạo nhận thức an ninh mạng cho nhân viên</li>
                        <li>Triển khai giải pháp xác thực đa yếu tố</li>
                        <li>Cập nhật thường xuyên các bản vá bảo mật</li>
                        <li>Theo dõi và phân tích các hoạt động bất thường trong mạng</li>
                        <li>Thực hiện kiểm tra an ninh và đánh giá lỗ hổng định kỳ</li>
                    </ul>

                    <p>Các chuyên gia an ninh mạng đang tiếp tục theo dõi chiến dịch này và cung cấp các cập nhật mới nhất về các chỉ số xâm nhập và phương pháp phòng thủ hiệu quả.</p>
                    """,
                    "summary": "Phát hiện chiến dịch APT mới nhắm vào các tổ chức chính trị tại Đông Nam Á, đặc biệt là Việt Nam, sử dụng phương thức phishing tinh vi để đánh cắp thông tin nhạy cảm.",
                    "category": "An ninh mạng",
                    "image_path": "desgined/des1.png",
                    "author_id": 1
                },
                {
                    "title": "Lỗ hổng Server-Side Template Injection (SSTI): Hiểu và ngăn chặn",
                    "content": """
                    <p>Server-Side Template Injection (SSTI) là một loại lỗ hổng bảo mật nguy hiểm cho phép kẻ tấn công chèn mã độc vào các template được xử lý ở phía máy chủ. Bài viết này sẽ phân tích cách lỗ hổng này hoạt động và các biện pháp phòng chống.</p>

                    <h3>SSTI hoạt động như thế nào?</h3>
                    <p>Nhiều ứng dụng web sử dụng các template engine như Jinja2, Twig, FreeMarker để tạo nội dung động. Khi dữ liệu người dùng được đưa trực tiếp vào template mà không được kiểm tra kỹ lưỡng, kẻ tấn công có thể chèn các biểu thức template độc hại để:</p>
                    <ul>
                        <li>Truy cập các đối tượng nội bộ của ứng dụng</li>
                        <li>Đọc file hệ thống</li>
                        <li>Thực thi lệnh hệ thống</li>
                        <li>Đánh cắp thông tin nhạy cảm</li>
                    </ul>

                    <h3>Ví dụ về SSTI trong các template engine phổ biến</h3>
                    <p>Trong Jinja2 (Python), một payload đơn giản có thể là:</p>
                    <pre><code>{{config.__class__.__init__.__globals__['os'].popen('id').read()}}</code></pre>
                    <p>Payload này truy cập đối tượng 'os' và thực thi lệnh 'id' trên hệ thống.</p>

                    <p>Trong Twig (PHP), một payload có thể là:</p>
                    <pre><code>{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}</code></pre>

                    <h3>Phòng chống SSTI</h3>
                    <p>Để bảo vệ ứng dụng khỏi lỗ hổng SSTI, các nhà phát triển nên:</p>
                    <ol>
                        <li>Không bao giờ truyền dữ liệu người dùng trực tiếp vào các hàm render template</li>
                        <li>Sử dụng các template engine an toàn với sandboxing</li>
                        <li>Phân tách rõ ràng dữ liệu và code trong template</li>
                        <li>Kiểm tra và làm sạch input từ người dùng trước khi đưa vào template</li>
                        <li>Áp dụng nguyên tắc "least privilege" cho template engine</li>
                    </ol>

                    <h3>Kết luận</h3>
                    <p>SSTI là một lỗ hổng nguy hiểm có thể dẫn đến RCE (Remote Code Execution) nếu không được xử lý đúng cách. Việc hiểu rõ cách lỗ hổng này hoạt động và áp dụng các biện pháp phòng chống thích hợp là rất quan trọng để bảo vệ ứng dụng web.</p>
                    """,
                    "summary": "Phân tích chi tiết về lỗ hổng Server-Side Template Injection (SSTI), cách nó hoạt động và các biện pháp phòng chống để bảo vệ ứng dụng web khỏi các cuộc tấn công có thể dẫn đến thực thi mã từ xa.",
                    "category": "Bảo mật",
                    "image_path": "desgined/des2.jpg",
                    "author_id": 1
                }
            ]
            
            for post_data in blog_posts:
                post = BlogPost(**post_data)
                db.session.add(post)
                
            db.session.commit()
            print("✓ Sample blog posts added.")

if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('data.db'):
        init_db()
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=True)

"""
Flask app chính.

⚠️  lỗ hổng Broken Authentication với hai cơ chế:
    1. Username enumeration trong quá trình đăng ký
    2. Logic lỗi trong cơ chế khóa tài khoản khi đăng nhập sai nhiều lần
"""

from flask import (Flask, render_template, request, redirect, url_for,
                   session, g, abort, jsonify, flash)
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
@app.route("/profile")
def profile():
    if g.user is None:
        flash("Please login first!", "warning")
        return redirect(url_for("login"))
    return render_template("profile.html")

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
    flag = "VNPT{Broken_Authentication_Account_Lock_Bypass}"
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
            admin = User(username="admin", email="admin@lab", role="admin")
            admin.set_pw("admin123")  # Sử dụng mật khẩu đơn giản để có thể brute force
            user = User(username="guest", email="guest@lab")
            user.set_pw("guestpass")
            db.session.add_all([admin, user])
            db.session.commit()
            print("✓ Database seeded.")
            
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
                    "title": "Lỗ hổng zero-day trong Microsoft Exchange Server đang bị khai thác",
                    "content": """
                    <p>Microsoft vừa công bố một lỗ hổng zero-day nghiêm trọng trong Exchange Server đang bị tin tặc khai thác tích cực. Lỗ hổng này cho phép kẻ tấn công thực thi mã từ xa trên máy chủ Exchange mà không cần xác thực.</p>

                    <h3>Chi tiết về lỗ hổng</h3>
                    <p>Lỗ hổng này, được đánh dấu là CVE-2022-XXXXX với mức độ nghiêm trọng 9.8/10, ảnh hưởng đến tất cả các phiên bản Microsoft Exchange Server từ 2013 đến 2019. Kẻ tấn công có thể khai thác lỗ hổng này để thực thi mã từ xa với đặc quyền SYSTEM, cho phép chúng kiểm soát hoàn toàn máy chủ.</p>

                    <p>Theo phân tích của các chuyên gia, lỗ hổng nằm trong thành phần xử lý yêu cầu HTTP của Exchange Server, và kẻ tấn công có thể khai thác nó bằng cách gửi một yêu cầu HTTP đặc biệt đến máy chủ.</p>

                    <h3>Các dấu hiệu bị tấn công</h3>
                    <p>Các dấu hiệu cho thấy hệ thống đã bị xâm nhập bao gồm:</p>
                    <ul>
                        <li>Sự xuất hiện của các webshell trong thư mục C:\\inetpub\\wwwroot\\aspnet_client\\</li>
                        <li>Các quá trình PowerShell hoặc cmd.exe bất thường được khởi chạy bởi w3wp.exe</li>
                        <li>Các kết nối đáng ngờ đến các địa chỉ IP không xác định</li>
                        <li>Các tệp và thư mục mới được tạo trong thư mục hệ thống</li>
                    </ul>

                    <h3>Biện pháp khắc phục</h3>
                    <p>Microsoft đã phát hành bản vá khẩn cấp cho lỗ hổng này và khuyến nghị tất cả các tổ chức sử dụng Exchange Server cần cập nhật ngay lập tức. Trong trường hợp không thể áp dụng bản vá ngay, Microsoft cũng cung cấp các biện pháp giảm thiểu tạm thời:</p>
                    <ol>
                        <li>Tắt dịch vụ Outlook Web Access (OWA) nếu không cần thiết</li>
                        <li>Hạn chế quyền truy cập vào Exchange Server từ bên ngoài</li>
                        <li>Triển khai các quy tắc tường lửa để chặn các yêu cầu đáng ngờ</li>
                        <li>Theo dõi các nhật ký hệ thống để phát hiện các hoạt động bất thường</li>
                    </ol>

                    <p>Các chuyên gia an ninh mạng khuyến nghị các tổ chức nên ưu tiên việc cập nhật các máy chủ Exchange đang tiếp xúc với internet, đồng thời kiểm tra xem hệ thống đã bị xâm nhập hay chưa.</p>
                    """,
                    "summary": "Microsoft phát hiện lỗ hổng zero-day nguy hiểm trong Exchange Server đang bị khai thác. Lỗ hổng cho phép thực thi mã từ xa mà không cần xác thực, ảnh hưởng tất cả phiên bản từ 2013-2019.",
                    "category": "Bảo mật",
                    "image_path": "desgined/des2.jpg",
                    "author_id": 1
                },
                {
                    "title": "Hướng dẫn bảo mật cho người dùng di động",
                    "content": """
                    <p>Trong thời đại kỹ thuật số hiện nay, điện thoại thông minh đã trở thành một phần không thể thiếu trong cuộc sống hàng ngày. Tuy nhiên, với việc lưu trữ ngày càng nhiều thông tin cá nhân và tài chính trên các thiết bị di động, việc đảm bảo an toàn cho chúng trở nên quan trọng hơn bao giờ hết.</p>

                    <h3>Cập nhật phần mềm thường xuyên</h3>
                    <p>Các bản cập nhật phần mềm thường xuyên bao gồm các bản vá bảo mật quan trọng để khắc phục các lỗ hổng đã được phát hiện. Hãy đảm bảo rằng hệ điều hành và tất cả các ứng dụng trên thiết bị của bạn luôn được cập nhật lên phiên bản mới nhất.</p>

                    <h3>Sử dụng mật khẩu mạnh và xác thực sinh trắc học</h3>
                    <p>Bảo vệ thiết bị của bạn bằng mật khẩu mạnh, mã PIN phức tạp hoặc các phương thức xác thực sinh trắc học như vân tay hoặc nhận dạng khuôn mặt. Tránh sử dụng các mẫu mở khóa đơn giản hoặc thông tin dễ đoán như ngày sinh.</p>

                    <h3>Cẩn thận khi tải và cài đặt ứng dụng</h3>
                    <p>Chỉ tải ứng dụng từ các cửa hàng ứng dụng chính thức như Google Play Store hoặc Apple App Store. Trước khi cài đặt, hãy kiểm tra đánh giá, xếp hạng và quyền mà ứng dụng yêu cầu. Đừng cài đặt ứng dụng yêu cầu quyền truy cập không cần thiết.</p>

                    <h3>Sử dụng mạng Wi-Fi an toàn</h3>
                    <p>Tránh kết nối với các mạng Wi-Fi công cộng không được bảo vệ khi thực hiện các giao dịch nhạy cảm. Nếu cần sử dụng Wi-Fi công cộng, hãy xem xét việc sử dụng VPN (Mạng Riêng Ảo) để mã hóa dữ liệu của bạn.</p>

                    <h3>Bật tính năng tìm thiết bị</h3>
                    <p>Cả Android và iOS đều cung cấp tính năng cho phép bạn định vị, khóa hoặc xóa dữ liệu từ xa nếu thiết bị bị mất hoặc đánh cắp. Hãy đảm bảo rằng tính năng này được bật trên thiết bị của bạn.</p>

                    <h3>Sao lưu dữ liệu thường xuyên</h3>
                    <p>Sao lưu dữ liệu quan trọng trên thiết bị của bạn thường xuyên để tránh mất dữ liệu trong trường hợp thiết bị bị mất, hư hỏng hoặc bị tấn công bởi ransomware.</p>

                    <h3>Cảnh giác với các nỗ lực lừa đảo</h3>
                    <p>Đừng nhấp vào các liên kết hoặc tải xuống tệp đính kèm từ các nguồn không xác định. Cảnh giác với các tin nhắn SMS hoặc email phishing yêu cầu thông tin cá nhân hoặc tài chính.</p>

                    <h3>Sử dụng ứng dụng bảo mật</h3>
                    <p>Xem xét việc cài đặt một ứng dụng bảo mật từ nhà cung cấp uy tín để bảo vệ thiết bị của bạn khỏi phần mềm độc hại, theo dõi hoạt động trực tuyến và cung cấp các tính năng bảo mật bổ sung.</p>

                    <p>Bằng cách tuân theo các biện pháp bảo mật cơ bản này, bạn có thể giảm đáng kể nguy cơ bị tấn công mạng và bảo vệ thông tin cá nhân trên thiết bị di động của mình.</p>
                    """,
                    "summary": "Hướng dẫn toàn diện về cách bảo vệ thiết bị di động khỏi các mối đe dọa an ninh mạng, bao gồm các biện pháp như cập nhật phần mềm, sử dụng mật khẩu mạnh và thận trọng khi tải ứng dụng.",
                    "category": "Kiến thức",
                    "image_path": "desgined/des3.png",
                    "author_id": 1
                },
                {
                    "title": "Phân tích kỹ thuật mã độc tống tiền (Ransomware)",
                    "content": """
                    <p>Ransomware là một loại mã độc nguy hiểm đang gây ra nhiều thiệt hại cho cá nhân và tổ chức trên toàn cầu. Bài viết này sẽ phân tích kỹ thuật hoạt động của ransomware và cách phòng chống hiệu quả.</p>

                    <h3>Cơ chế hoạt động của Ransomware</h3>
                    <p>Ransomware thường xâm nhập vào hệ thống thông qua các phương thức sau:</p>
                    <ul>
                        <li><strong>Email lừa đảo (Phishing)</strong>: Người dùng nhận được email chứa tệp đính kèm hoặc liên kết độc hại.</li>
                        <li><strong>Lỗ hổng bảo mật</strong>: Khai thác các lỗ hổng trong hệ điều hành hoặc ứng dụng chưa được vá.</li>
                        <li><strong>Tải xuống không an toàn</strong>: Tải phần mềm từ các nguồn không đáng tin cậy.</li>
                        <li><strong>Drive-by download</strong>: Tự động tải xuống khi truy cập trang web độc hại.</li>
                    </ul>
                    
                    <h3>Quá trình mã hóa dữ liệu</h3>
                    <p>Sau khi xâm nhập thành công, ransomware sẽ thực hiện các bước sau:</p>
                    <ol>
                        <li>Thiết lập kết nối với máy chủ điều khiển (C&C) để nhận khóa mã hóa</li>
                        <li>Quét hệ thống tìm kiếm các tệp tin quan trọng như tài liệu, hình ảnh, video</li>
                        <li>Mã hóa các tệp tin bằng thuật toán mã hóa mạnh như RSA, AES</li>
                        <li>Xóa các bản sao lưu và tệp shadow copy để ngăn khôi phục</li>
                        <li>Hiển thị thông báo tống tiền và hướng dẫn thanh toán</li>
                    </ol>
                    
                    <h3>Các biến thể Ransomware phổ biến</h3>
                    <p>Một số biến thể ransomware nguy hiểm đang hoạt động:</p>
                    <ul>
                        <li><strong>REvil/Sodinokibi</strong>: Hoạt động theo mô hình Ransomware-as-a-Service (RaaS), cho phép các tin tặc thuê và sử dụng.</li>
                        <li><strong>LockBit</strong>: Tự lan truyền trong mạng nội bộ, sử dụng các công cụ hợp pháp để tránh phát hiện.</li>
                        <li><strong>Conti</strong>: Sử dụng kỹ thuật mã hóa nhanh, đồng thời đánh cắp dữ liệu trước khi mã hóa.</li>
                        <li><strong>WannaCry</strong>: Từng gây ra đại dịch toàn cầu năm 2017, lan truyền qua lỗ hổng SMB.</li>
                    </ul>
                    
                    <h3>Phương pháp phòng chống Ransomware</h3>
                    <p>Để bảo vệ khỏi ransomware, tổ chức và cá nhân nên áp dụng các biện pháp sau:</p>
                    <ul>
                        <li>Cập nhật thường xuyên hệ điều hành và các ứng dụng</li>
                        <li>Sao lưu dữ liệu quan trọng theo quy tắc 3-2-1 (3 bản sao, 2 loại phương tiện, 1 bản ngoại tuyến)</li>
                        <li>Cài đặt giải pháp bảo mật với khả năng phát hiện hành vi bất thường</li>
                        <li>Tập huấn nhận thức an ninh mạng cho nhân viên</li>
                        <li>Triển khai chính sách kiểm soát truy cập tối thiểu</li>
                        <li>Ngăn chặn các tệp đính kèm và trang web độc hại</li>
                        <li>Phân đoạn mạng để hạn chế sự lây lan</li>
                    </ul>
                    
                    <h3>Kết luận</h3>
                    <p>Ransomware tiếp tục phát triển với các kỹ thuật tấn công tinh vi hơn. Việc hiểu rõ cơ chế hoạt động và áp dụng các biện pháp phòng chống toàn diện là chìa khóa để bảo vệ tổ chức và cá nhân khỏi loại mã độc nguy hiểm này. Đặc biệt, chiến lược "phòng ngừa tốt hơn chữa trị" là cách tiếp cận hiệu quả nhất đối với mối đe dọa ransomware.</p>
                    """,
                    "summary": "Phân tích chi tiết về cơ chế hoạt động của ransomware, các biến thể phổ biến và phương pháp phòng chống hiệu quả. Bài viết cung cấp cái nhìn kỹ thuật về quy trình tấn công và mã hóa dữ liệu của loại mã độc nguy hiểm này.",
                    "category": "Bảo mật",
                    "image_path": "desgined/des4.png",
                    "author_id": 1
                },
                {
                    "title": "Thực hành triển khai bảo mật theo tiêu chuẩn Zero Trust",
                    "content": """
                    <p>Mô hình bảo mật Zero Trust là một cách tiếp cận hiện đại đang được nhiều tổ chức áp dụng để tăng cường an ninh hệ thống. Bài viết này sẽ hướng dẫn các bước thực tế để triển khai mô hình Zero Trust trong doanh nghiệp.</p>

                    <h3>Nguyên tắc cốt lõi của Zero Trust</h3>
                    <p>Mô hình Zero Trust dựa trên nguyên tắc "không bao giờ tin tưởng, luôn xác minh" và bao gồm các yếu tố cơ bản sau:</p>
                    <ul>
                        <li>Xác thực mọi người dùng, thiết bị và kết nối trước khi cấp quyền truy cập</li>
                        <li>Áp dụng quyền truy cập tối thiểu (Least Privilege)</li>
                        <li>Kiểm soát và giám sát liên tục mọi hoạt động trong mạng</li>
                        <li>Phân đoạn mạng vi mô (Micro-segmentation)</li>
                        <li>Bảo mật dữ liệu ở mọi trạng thái (lưu trữ, truyền tải, sử dụng)</li>
                    </ul>
                    
                    <h3>Các bước triển khai Zero Trust</h3>
                    
                    <h4>1. Xác định tài sản cần bảo vệ</h4>
                    <p>Bước đầu tiên là nhận diện và phân loại các tài sản quan trọng:</p>
                    <ul>
                        <li>Lập danh sách các ứng dụng và dữ liệu quan trọng</li>
                        <li>Xác định người dùng và vai trò truy cập</li>
                        <li>Phân loại dữ liệu theo mức độ nhạy cảm</li>
                        <li>Xây dựng sơ đồ luồng dữ liệu</li>
                    </ul>
                    
                    <h4>2. Triển khai xác thực đa yếu tố (MFA)</h4>
                    <p>MFA là nền tảng quan trọng của Zero Trust:</p>
                    <ul>
                        <li>Áp dụng MFA cho tất cả người dùng và hệ thống</li>
                        <li>Kết hợp nhiều yếu tố xác thực: mật khẩu, token, sinh trắc học</li>
                        <li>Sử dụng xác thực thích ứng dựa trên ngữ cảnh và rủi ro</li>
                        <li>Tích hợp với dịch vụ quản lý định danh (IDaaS)</li>
                    </ul>
                    
                    <h4>3. Triển khai quản lý định danh và truy cập (IAM)</h4>
                    <p>Hệ thống IAM hiệu quả sẽ:</p>
                    <ul>
                        <li>Quản lý vòng đời định danh người dùng</li>
                        <li>Tự động cấp phát và thu hồi quyền truy cập</li>
                        <li>Thực thi chính sách truy cập dựa trên vai trò (RBAC)</li>
                        <li>Tích hợp với hệ thống xác thực trên đám mây và tại chỗ</li>
                    </ul>
                    
                    <h4>4. Phân đoạn mạng vi mô</h4>
                    <p>Để hạn chế phạm vi tấn công:</p>
                    <ul>
                        <li>Chia nhỏ mạng thành các phân đoạn logic</li>
                        <li>Triển khai tường lửa thế hệ mới (NGFW) và tường lửa ứng dụng web (WAF)</li>
                        <li>Áp dụng chính sách truy cập theo nguyên tắc "deny by default"</li>
                        <li>Sử dụng công nghệ SDN (Software-Defined Networking) để quản lý phân đoạn</li>
                    </ul>
                    
                    <h4>5. Giám sát liên tục và phân tích hành vi</h4>
                    <p>Hệ thống giám sát hiệu quả sẽ bao gồm:</p>
                    <ul>
                        <li>Phân tích hành vi người dùng và thực thể (UEBA)</li>
                        <li>Hệ thống phát hiện và phản ứng điểm cuối (EDR)</li>
                        <li>Thu thập và phân tích nhật ký tập trung (SIEM)</li>
                        <li>Giám sát trải nghiệm số của người dùng (DEM)</li>
                    </ul>
                    
                    <h4>6. Bảo mật dữ liệu</h4>
                    <p>Để bảo vệ dữ liệu ở mọi trạng thái:</p>
                    <ul>
                        <li>Mã hóa dữ liệu khi lưu trữ và truyền tải</li>
                        <li>Triển khai các giải pháp DLP (Data Loss Prevention)</li>
                        <li>Quản lý quyền truy cập dữ liệu chi tiết</li>
                        <li>Áp dụng công nghệ CASB cho ứng dụng đám mây</li>
                    </ul>
                    
                    <h3>Thách thức và giải pháp</h3>
                    <p>Triển khai Zero Trust có thể gặp một số thách thức:</p>
                    <ul>
                        <li><strong>Hệ thống legacy</strong>: Sử dụng proxy và gateway bảo mật để bọc các hệ thống cũ</li>
                        <li><strong>Tích hợp đa môi trường</strong>: Áp dụng giải pháp bảo mật đa đám mây (multi-cloud)</li>
                        <li><strong>Trải nghiệm người dùng</strong>: Cân bằng giữa bảo mật và sự tiện lợi</li>
                        <li><strong>Chi phí triển khai</strong>: Xây dựng lộ trình triển khai theo giai đoạn</li>
                    </ul>
                    
                    <h3>Kết luận</h3>
                    <p>Mô hình bảo mật Zero Trust không phải là một giải pháp có thể triển khai ngay lập tức, mà là một hành trình chuyển đổi liên tục. Bằng cách áp dụng từng bước theo lộ trình phù hợp, các tổ chức có thể cải thiện đáng kể tư thế bảo mật và giảm thiểu rủi ro trong bối cảnh mối đe dọa ngày càng phức tạp.</p>
                    """,
                    "summary": "Hướng dẫn thực tiễn về cách triển khai mô hình bảo mật Zero Trust trong doanh nghiệp. Bài viết trình bày chi tiết từng bước thực hiện, từ xác định tài sản, triển khai xác thực đa yếu tố, quản lý định danh, phân đoạn mạng vi mô đến giám sát liên tục và bảo mật dữ liệu.",
                    "category": "An ninh mạng",
                    "image_path": "desgined/des1.png",
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

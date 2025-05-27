"""
Flask app chính cho A04-Insecure Design Challenge.

⚠️ Lab này trình diễn lỗi OWASP A04:2021 - Insecure Design:
    1. Server tin tưởng dữ liệu (giá tiền) do client gửi lên
    2. Client thao túng giá để nhận voucher đặc biệt
"""

import os
from flask import Flask, session
from flask_login import LoginManager, current_user
from models import db, User, Product
from routes import auth, cart, checkout, main
from datetime import datetime

def create_app():
    app = Flask(__name__)
    
    # Cấu hình cơ bản
    app.config['SECRET_KEY'] = 'insecuredesign_ctf_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Khởi tạo database
    db.init_app(app)
    
    # Đăng ký blueprints
    app.register_blueprint(auth.bp)
    app.register_blueprint(cart.bp)
    app.register_blueprint(checkout.bp)
    app.register_blueprint(main.bp)
    
    # Khởi tạo LoginManager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Vui lòng đăng nhập để truy cập trang này'
    login_manager.login_message_category = 'warning'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        # Vì đang sử dụng Flask-Login, cần định nghĩa hàm này
        # để tải người dùng từ session
        return User.query.get(int(user_id))
    
    # Thêm biến toàn cục cho templates
    @app.context_processor
    def inject_cart_count():
        cart_count = 0
        if current_user.is_authenticated and 'cart' in session:
            cart_count = sum(item['qty'] for item in session['cart'])
        return dict(cart_count=cart_count)
    
    return app

def init_db(app):
    """Khởi tạo cơ sở dữ liệu với dữ liệu mẫu"""
    with app.app_context():
        db.create_all()
        
        # Kiểm tra nếu đã có dữ liệu
        if User.query.count() == 0:
            # Tạo người dùng mẫu
            user = User(username='alice')
            user.set_password('alice')
            db.session.add(user)
            
            # Tạo sản phẩm mẫu
            products = [
                Product(name='OWASP Sticker', 
                       price=10000, 
                       description='Sticker with OWASP logo', 
                       image='desgined/des3.png'),
                Product(name='Security T-Shirt', 
                       price=120000, 
                       description='Premium T-Shirt with cybersecurity design', 
                       image='desgined/des1.png'),
                Product(name='Hacker Hoodie', 
                       price=250000, 
                       description='Comfortable hoodie with hacker-inspired design', 
                       image='desgined/des2.jpg')
            ]
            db.session.add_all(products)
            db.session.commit()
            
            # Tạo file flag
            flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flag.txt')
            with open(flag_path, 'w') as f:
                f.write("VNPT{INSECURE_DESIGN_TRUSTING_CLIENT_DATA_IS_DANGEROUS}")
                
            print("✅ Database initialized with sample data")

if __name__ == '__main__':
    app = create_app()
    
    # Khởi tạo database nếu chưa tồn tại
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shop.db')
    if not os.path.exists(db_path):
        init_db(app)
    
    # Chạy ứng dụng
    app.run(host='0.0.0.0', port=5000, debug=True)

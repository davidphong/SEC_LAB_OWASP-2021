"""
Script khởi tạo cơ sở dữ liệu cho FailureAuth-lab
"""

import os
import sys

# Thêm thư mục hiện tại vào đường dẫn để import module
sys.path.append('.')

# Import các thành phần từ app.py
from app import app, db, User

def init_database():
    print("Bắt đầu khởi tạo cơ sở dữ liệu...")
    
    with app.app_context():
        # Tạo tất cả các bảng
        db.create_all()
        print("✓ Đã tạo schema database")
        
        # Chỉ tạo users mẫu nếu chưa có user nào
        if not User.query.first():
            # Admin user - sử dụng mật khẩu đơn giản để có thể brute force
            admin = User(
                username="admin", 
                email="admin@lab", 
                role="admin",
                full_name="Admin User",
                phone_number="0123456789",
                address="123 Admin Street",
                city="Hanoi",
                country="Vietnam",
                bio="I am the administrator of this website",
                company="Security Lab",
                job_title="System Administrator",
                website="https://example.com/admin",
                social_media="@admin"
            )
            # Sử dụng mật khẩu đơn giản để có thể brute force
            admin.set_pw("admin123")
            
            # Regular user
            user = User(
                username="guest", 
                email="guest@lab",
                full_name="Guest User",
                phone_number="9876543210",
                address="456 Guest Avenue",
                city="Ho Chi Minh",
                country="Vietnam",
                bio="Just a regular user exploring this website",
                company="Guest Corp",
                job_title="Security Enthusiast",
                website="https://example.com/guest",
                social_media="@guest"
            )
            user.set_pw("guest")
            
            # Add users to database
            db.session.add_all([admin, user])
            db.session.commit()
            print("✓ Đã thêm dữ liệu mẫu")
        else:
            print("× Bỏ qua thêm dữ liệu mẫu (đã có dữ liệu)")
    
    print("Khởi tạo cơ sở dữ liệu hoàn tất!")

if __name__ == "__main__":
    # Xóa database cũ nếu có
    if os.path.exists('data.db'):
        os.remove('data.db')
        print("✓ Đã xóa database cũ")
    
    # Khởi tạo database mới
    init_database() 

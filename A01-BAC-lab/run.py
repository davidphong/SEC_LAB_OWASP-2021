import sys

# Thêm thư mục hiện tại vào đường dẫn để import module
sys.path.append('.')

from app import app, init_db
import os

if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('data.db'):
        init_db()
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=True) 
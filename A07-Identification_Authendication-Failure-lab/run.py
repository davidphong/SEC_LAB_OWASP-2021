import sys
import os

# Thêm thư mục hiện tại vào đường dẫn để import module
sys.path.append('.')

from app import app, init_db

if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('data.db'):
        init_db()
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5001))
    
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=True) 

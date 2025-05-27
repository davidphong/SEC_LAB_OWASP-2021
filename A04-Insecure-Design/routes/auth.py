from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from models import User, db

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Tên đăng nhập hoặc mật khẩu không đúng', 'danger')
            return render_template('login.html')
            
        login_user(user)
        flash(f'Xin chào, {user.username}!', 'success')
        
        # Redirect to next page or homepage
        next_page = request.args.get('next')
        return redirect(next_page or url_for('main.index'))
        
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Bạn đã đăng xuất thành công', 'info')
    return redirect(url_for('main.index')) 
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_required, current_user
from models import Product, db

bp = Blueprint('cart', __name__)

@bp.route('/cart')
@login_required
def view_cart():
    # Get cart from session
    cart = session.get('cart', [])
    cart_items = []
    total = 0
    
    # Fetch product details for items in cart
    for item in cart:
        product = Product.query.get(item['id'])
        if product:
            item_total = product.price * item['qty']
            cart_items.append({
                'product': product,
                'quantity': item['qty'],
                'total': item_total
            })
            total += item_total
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@bp.route('/api/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    data = request.get_json()
    product_id = data.get('id')
    quantity = data.get('qty', 1)
    
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400
        
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    # Initialize cart if needed
    if 'cart' not in session:
        session['cart'] = []
    
    # Check if product already in cart
    for item in session['cart']:
        if item['id'] == product_id:
            item['qty'] += quantity
            session.modified = True
            return jsonify({
                'message': f'{product.name} quantity updated in cart',
                'cart_count': sum(item['qty'] for item in session['cart'])
            })
    
    # Add new item to cart
    session['cart'].append({'id': product_id, 'qty': quantity})
    session.modified = True
    
    return jsonify({
        'message': f'{product.name} added to cart',
        'cart_count': sum(item['qty'] for item in session['cart'])
    })

@bp.route('/api/cart/remove', methods=['POST'])
@login_required
def remove_from_cart():
    data = request.get_json()
    product_id = data.get('id')
    
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400
    
    if 'cart' not in session:
        return jsonify({'message': 'Cart is empty'})
    
    # Remove product from cart
    session['cart'] = [item for item in session['cart'] if item['id'] != product_id]
    session.modified = True
    
    return jsonify({
        'message': 'Product removed from cart',
        'cart_count': sum(item['qty'] for item in session['cart'])
    })

@bp.route('/api/cart/clear', methods=['POST'])
@login_required
def clear_cart():
    session.pop('cart', None)
    return jsonify({'message': 'Cart cleared'}) 
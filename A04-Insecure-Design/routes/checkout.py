from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_required, current_user
from models import db, Product, Order, OrderItem
import os

bp = Blueprint('checkout', __name__)

@bp.route('/checkout')
@login_required
def checkout_page():
    # Check if cart is empty
    cart = session.get('cart', [])
    if not cart:
        flash('Giỏ hàng của bạn đang trống', 'warning')
        return redirect(url_for('main.index'))
        
    # Fetch product details for items in cart
    cart_items = []
    total = 0
    
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
    
    return render_template('checkout.html', cart_items=cart_items, total=total)

@bp.route('/api/checkout', methods=['POST'])
@login_required
def checkout():
    # Get JSON data from request
    data = request.get_json()
    
    # Expected format:
    # {
    #   "items": [{"id": 1, "qty": 2}, {"id": 2, "qty": 1}],
    #   "totalPrice": 20000  <-- VULNERABLE: Server trusts client-calculated total
    # }
    
    # ⚠️ INSECURE DESIGN: Server blindly trusts client-calculated totalPrice
    # Proper design would require server to calculate total from items and database prices
    
    # Create order with client-provided total
    order = Order(
        user_id=current_user.id,
        total=data.get('totalPrice', 0)  # ❌ Trusting client-sent value
    )
    db.session.add(order)
    db.session.commit()
    
    # Add order items
    items = data.get('items', [])
    for item in items:
        product_id = item.get('id')
        quantity = item.get('qty', 1)
        
        if product_id:
            order_item = OrderItem(
                order_id=order.id,
                product_id=product_id,
                quantity=quantity
            )
            db.session.add(order_item)
    
    db.session.commit()
    
    # Clear cart after successful checkout
    session.pop('cart', None)
    
    # Check for special offer (FLAG)
    flag = ""
    a = False
    for _ in order.items:
        if _.quantity > 10:
            a = True
    if order.total < 1000 and a:  # If price < 1,000 VND, provide flag
        # Try to read flag from file
        try:
            flag_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'flag.txt')
            if os.path.exists(flag_path):
                with open(flag_path, 'r') as f:
                    flag = f.read().strip()
            else:
                flag = "VNPT{INSECURE_DESIGN_TRUSTING_CLIENT_DATA_IS_DANGEROUS}"
        except:
            flag = "VNPT{INSECURE_DESIGN_TRUSTING_CLIENT_DATA_IS_DANGEROUS}"
    
    return jsonify({
        "invoice": f"INV-{order.id}",
        "orderTotal": order.total,
        "flag": flag  # Empty unless total < 1000
    }), 201 
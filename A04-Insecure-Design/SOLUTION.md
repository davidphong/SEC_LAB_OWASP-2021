# A04:2021 - Insecure Design: Giải pháp

## Mô tả lỗ hổng

Ứng dụng OWASP Mini Shop có lỗ hổng thiết kế không an toàn trong quy trình thanh toán. Cụ thể:

1. **Thiết kế sai**: Server tin tưởng dữ liệu giá tiền (totalPrice) do client gửi lên
2. **Thiếu kiểm tra**: Backend không tính toán lại tổng tiền dựa trên giá sản phẩm thực tế trong cơ sở dữ liệu

## Cách khai thác

### Bước 1: Đăng nhập và thêm sản phẩm vào giỏ hàng

1. Đăng nhập với tài khoản: `alice/alice`
2. Thêm một sản phẩm bất kỳ vào giỏ hàng
3. Truy cập trang thanh toán

### Bước 2: Chặn và sửa đổi request thanh toán

Sử dụng công cụ như Browser DevTools hoặc Burp Suite:

1. Mở DevTools (F12) và chuyển đến tab Network
2. Nhấn nút "Xác nhận đặt hàng"
3. Chặn request `POST /api/checkout`
4. Sửa đổi giá trị `totalPrice` thành một giá trị nhỏ (ví dụ: 1)

```json
// Yêu cầu gốc
{
  "items": [{"id": 1, "qty": 1}],
  "totalPrice": 10000
}

// Yêu cầu đã sửa đổi
{
  "items": [{"id": 1, "qty": 1}],
  "totalPrice": 1
}
```

5. Gửi request đã sửa đổi

### Bước 3: Nhận FLAG

Sau khi gửi request đã sửa đổi, server sẽ:
1. Tin tưởng giá trị `totalPrice` từ client
2. Phát hiện giá trị nhỏ hơn 1000 VNĐ
3. Hiển thị FLAG trong phản hồi

```json
{
  "invoice": "INV-X",
  "orderTotal": 1,
  "flag": "OWASP{INSECURE_DESIGN_TRUSTING_CLIENT_DATA_IS_DANGEROUS}"
}
```

## Giải thích kỹ thuật

### Mã nguồn có lỗ hổng

```python
@bp.route('/api/checkout', methods=['POST'])
@login_required
def checkout():
    data = request.get_json()
    
    # ⚠️ INSECURE DESIGN: Server blindly trusts client-calculated totalPrice
    order = Order(
        user_id=current_user.id,
        total=data.get('totalPrice', 0)  # ❌ Trusting client-sent value
    )
    db.session.add(order)
    db.session.commit()
    
    # ... thêm các mục đơn hàng ...
    
    # Check for special offer (FLAG)
    flag = ""
    if order.total < 1000:  # If price < 1,000 VND, provide flag
        flag = "OWASP{INSECURE_DESIGN_TRUSTING_CLIENT_DATA_IS_DANGEROUS}"
    
    return jsonify({
        "invoice": f"INV-{order.id}",
        "orderTotal": order.total,
        "flag": flag
    }), 201
```

### Mã JavaScript gửi dữ liệu từ client

```javascript
// ⚠️ Lỗ hổng Insecure Design: Client tính toán và gửi tổng tiền
const data = {
    items: items,
    totalPrice: {{ total }}  // Client tính toán và gửi tổng tiền
};
```

## Cách khắc phục

### 1. Tính toán lại tổng tiền ở phía server

```python
@bp.route('/api/checkout', methods=['POST'])
@login_required
def checkout():
    data = request.get_json()
    
    # Chỉ nhận danh sách items từ client
    items = data.get('items', [])
    
    # Tính toán lại tổng tiền dựa trên giá trong database
    total = 0
    for item in items:
        product = Product.query.get(item.get('id'))
        if product:
            total += product.price * item.get('qty', 1)
    
    # Tạo đơn hàng với tổng tiền đã tính toán lại
    order = Order(
        user_id=current_user.id,
        total=total  # ✅ Sử dụng giá trị đã tính toán lại
    )
    # ...
```

### 2. Thêm kiểm tra và ghi nhật ký

```python
# Ghi nhật ký nếu phát hiện sự khác biệt giữa giá client và server
client_total = data.get('totalPrice', 0)
if client_total != total:
    app.logger.warning(
        f"Price manipulation detected! User: {current_user.username}, "
        f"Client total: {client_total}, Server total: {total}"
    )
```

### 3. Áp dụng nguyên tắc thiết kế an toàn

- **Không tin tưởng đầu vào từ client**: Luôn kiểm tra và xác thực dữ liệu
- **Defense in depth**: Thêm nhiều lớp bảo vệ
- **Source of truth**: Server phải là nguồn dữ liệu đáng tin cậy duy nhất
- **Threat modeling**: Phân tích các mối đe dọa tiềm ẩn trong thiết kế

## Tài nguyên học tập

- [OWASP Top 10 2021: A04 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Cheat Sheet: Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [OWASP ASVS - Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) 
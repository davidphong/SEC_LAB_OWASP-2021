# A04:2021 - Insecure Design

## Mô tả lab

Lab này trình diễn lỗi OWASP A04:2021 - Insecure Design (Thiết kế không an toàn) thông qua một ứng dụng web cửa hàng mini.

### Kịch bản lỗ hổng

Ứng dụng có lỗ hổng thiết kế không an toàn trong quy trình thanh toán:

1. **Thiết kế sai**: Server tin tưởng dữ liệu nhạy cảm (giá tiền) do client gửi lên
2. **Hậu quả**: Client có thể thao túng giá tiền để nhận voucher đặc biệt (FLAG)

> **Lỗi cốt lõi**: Logic tính tiền nằm ở frontend, backend chỉ "ghi sổ" mà không kiểm tra lại.

## Cài đặt

### Yêu cầu

- Python 3.8+
- Flask và các thư viện phụ thuộc

### Cài đặt thủ công

```bash
# Cài đặt các thư viện cần thiết
pip install -r requirements.txt

# Chạy ứng dụng
python app.py
```

### Sử dụng Docker

```bash
# Build Docker image
docker build -t a04_insecure_shop .

# Chạy container
docker run -p 5000:5000 a04_insecure_shop
```

## Sử dụng

1. Truy cập ứng dụng tại `http://localhost:5000`
2. Đăng nhập với tài khoản mẫu: `alice/alice`
3. Thêm sản phẩm vào giỏ hàng và tiến hành thanh toán
4. Tìm và khai thác lỗ hổng thiết kế không an toàn để lấy FLAG

## Mục tiêu học tập

* Hiểu về lỗi Insecure Design: lỗi logic nghiệp vụ ngay từ khâu thiết kế
* Nhận biết sự nguy hiểm của việc tin tưởng dữ liệu do client gửi lên
* Học cách thiết kế hệ thống an toàn với nguyên tắc "không tin tưởng đầu vào"

## Tài nguyên tham khảo

- [OWASP Top 10 2021: A04 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Cheat Sheet: Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Business Logic Security](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html) 
# Virus Scanner Web Application

Ứng dụng web tương tự VirusTotal để quét file với ClamAV Database.

## Tính năng

- ✅ Upload file qua drag & drop hoặc click
- ✅ Quét file với 413,600+ virus signatures từ ClamAV
- ✅ Hiển thị thông tin file (MD5, SHA256, kích thước)
- ✅ Phát hiện và hiển thị các mối đe dọa
- ✅ Giao diện đẹp, responsive
- ✅ Real-time scanning với progress indicator

## Cài đặt

1. Vào thư mục web:
```bash
cd web
```

2. Cài đặt dependencies:
```bash
pip install -r requirements.txt
```

3. Đảm bảo file `db/virus_signatures.txt` tồn tại (đã có sẵn)

4. Chạy server:
```bash
python3 app.py
```

5. Mở trình duyệt và truy cập: `http://localhost:8080`

**Lưu ý:** Nếu port 8080 bị chiếm, bạn có thể thay đổi bằng cách:
```bash
PORT=3000 python3 app.py
```

## Cấu trúc thư mục

```
.
├── app.py                 # Flask server
├── templates/
│   └── index.html        # Frontend HTML
├── static/
│   ├── css/
│   │   └── style.css     # Styles
│   └── js/
│       └── main.js       # JavaScript
├── db/
│   └── virus_signatures.txt  # Virus signatures database
├── uploads/              # Thư mục lưu file upload (tự động tạo)
└── requirements.txt      # Python dependencies
```

## API Endpoints

- `GET /` - Trang chủ
- `POST /upload` - Upload và scan file
- `GET /health` - Health check và số lượng signatures

## Lưu ý

- File tối đa: 100MB
- Signatures được load một lần khi start server
- File upload được lưu trong thư mục `uploads/`

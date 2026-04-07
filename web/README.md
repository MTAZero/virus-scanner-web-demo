# Virus Scanner Web Application

Ứng dụng web tương tự VirusTotal để quét file với ClamAV Database.

## Tính năng

- ✅ Upload file qua drag & drop hoặc click
- ✅ Quét file với 413,600+ virus signatures từ ClamAV
- ✅ Hiển thị thông tin file (MD5, SHA256, kích thước)
- ✅ Phát hiện và hiển thị các mối đe dọa
- ✅ **CNN Malimg (theo [cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN)):** chuyển byte → ảnh xám kiểu Malimg (`hex2img`), resize **256×256**, nhân 3 kênh; mạng **Sequential + softmax** như `combined_classifier_val.ipynb` (đa lớp, gồm **Benign** nếu train đủ 26 lớp). Kết quả chỉ **tham khảo**, không thay thế chữ ký. Giải thích đầy đủ: **`readme-ml.md`**.
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

4. (Tùy chọn) Huấn luyện model CNN — xem **Học máy (Malimg / cridin1)**. Nếu chưa có model, server vẫn chạy; ưu tiên load `ml/malimg_model.keras`, fallback `ml/malware_cnn.keras` (mô hình nhị phân cũ nếu còn).

5. Chạy server:
```bash
python3 app.py
```

6. Mở trình duyệt và truy cập: `http://localhost:8080`

**Lưu ý:** Nếu port 8080 bị chiếm:
```bash
PORT=3000 python3 app.py
```

## Học máy (Malimg / cridin1)

Tham chiếu chính: **[cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN)** — chuyển đổi byte trong `utils/data_conversion.ipynb`, kiến trúc CNN trong `combined_classifier/combined_classifier_val.ipynb`.

### Pipeline trong repo này

1. Đọc file nhị phân, gom byte thành lưới **(n, 16)** rồi reshape ảnh xám theo công thức `hex2img` (b là lũy thừa 2 của 2).
2. Resize **256×256**, stack 3 kênh giống ảnh RGB đưa vào `ImageDataGenerator(rescale=1/255)`.
3. CNN: Conv(64)→Pool→Conv(32)→Pool→Conv(32)→Pool→Conv(16)→Pool→Dropout→Dense(128)→Dense(50)→**softmax** (`num_classes` lớp).

### Huấn luyện

Trong thư mục `web/`:

```bash
# Synthetic 26 lớp (đúng tên Malimg combined) — demo nhanh
python train_cnn.py

# Ảnh PNG đã ghép 26 lớp (Malimg + Benign) — sau khi tải theo ../datasets/README.md
python train_cnn.py --malimg-png-root ../datasets/malimg_combined

# File nhị phân thô (PE…) trong cấu trúc: root/TênLớp/file.bin
python train_cnn.py --malimg-bytes-root /path/to/raw_samples_by_class
```

Tham số: `--epochs`, `--batch-size`, `--img-size` (mặc định **256**), `--samples-per-class` (synthetic).

**Output:**

- `ml/malimg_model.keras` — model Keras
- `ml/malimg_metadata.json` — thứ tự `class_names` (phải khớp lúc train để softmax đúng nhãn)

Nếu vẫn giữ file **`ml/malware_cnn.keras`** cũ (1 neuron sigmoid), inference sẽ dùng mã hóa legacy 64×256 theo thiết kế cũ.

### Lưu ý

- Kết quả CNN chỉ **tham khảo**; nên kết hợp quét **chữ ký ClamAV**.
- Dataset **Malimg** / benign đầy đủ cần tải và xử lý theo hướng dẫn repo gốc; synthetic chỉ để kiểm tra chuỗi train/infer.

## Cấu trúc thư mục

```
.
├── app.py
├── train_cnn.py
├── ml/
│   ├── class_names.py       # 26 tên lớp combined (mặc định khi không có metadata)
│   ├── encoding.py          # Malimg hex2img + resize RGB
│   ├── model_def.py         # Sequential cridin1
│   ├── inference.py
│   ├── malimg_model.keras   # (sau train)
│   ├── malimg_metadata.json # (sau train)
│   └── malware_cnn.keras    # (tùy chọn — model nhị phân cũ)
├── templates/
├── static/
├── db/
└── requirements.txt
```

## API Endpoints

- `GET /` - Trang chủ
- `POST /upload` - Upload và scan (chữ ký + `ml`: `mode` `malimg_cridin1` hoặc `legacy_binary`)
- `GET /health` - `ml_model_available`, `ml_model_path`

## Lưu ý

- File tối đa: 100MB
- Signatures được load một lần khi start server
- File upload được lưu trong thư mục `uploads/`

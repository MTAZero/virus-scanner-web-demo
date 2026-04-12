# Tóm tắt AI / học máy trong đồ án (bản báo cáo thầy)

Tài liệu **rút gọn tối đa**: chỉ các ý **cần nhất** để trình bày. Chi tiết lý thuyết và khớp code: **`doc-ai-hoc-may.md`**. Hướng dẫn chạy: **`readme-ml.md`**.

---

## 1. Vai trò AI trong project

- Hệ thống có **hai lớp phát hiện:** (1) **chữ ký** (hash MD5/SHA256, mẫu byte như ClamAV) — **không phải AI**; (2) **gợi ý học máy** bằng **CNN** trên ảnh hóa file — **có dùng AI**.
- CNN chỉ là **tham khảo**, **không thay** antivirus chữ ký.

## 2. Bài toán và ý tưởng

- **Đầu vào:** file nhị phân bất kỳ.
- **Cách làm:** biến byte thành **ảnh xám kiểu Malimg** (byte → lưới 2D → resize **256×256** → nhân **3 kênh** giống RGB để vào mạng quen ảnh màu).
- **Đầu ra:** xác suất trên **nhiều lớp** (các họ mã độc trong dataset Malimg + lớp **Benign** nếu train đủ), nhờ **softmax** ở tầng cuối.

## 3. Mạng nơ-ron (nói ngắn cho báo cáo)

- **Mạng nơ-ron** = nhiều lớp **nơ-ron**: mỗi nơ-ron nhận tổng có trọng số của đầu vào, cộng bias, rồi qua **hàm kích hoạt** (phi tuyến).
- **Huấn luyện:** so sánh dự đoán với nhãn bằng **hàm mất mát**; dùng **gradient** (đạo hàm) để **cập nhật dần** hàng triệu trọng số — thuật toán **lan truyền ngược** tính gradient tự động qua các lớp.
- **CNN** (mạng tích chập): phù hợp **ảnh** — học **mẫu cục bộ** (kernel trượt trên lưới), ít tham số hơn nối thẳng toàn bộ pixel.

## 4. Kiến trúc trong code (khái niệm)

- **Tháp Conv + MaxPool:** trích **đặc trưng** từ ảnh Malimg.
- **Dense + softmax:** gộp đặc trưng và **phân loại** \(K\) lớp.
- **Dropout:** giảm **học thuộc lòng** tập train.
- Framework: **TensorFlow / Keras**; tối ưu **Adam**; loss **categorical crossentropy** (phân loại nhiều lớp).

## 5. Dữ liệu (khái quát)

- Dataset kiểu **Malimg** (ảnh theo từng họ mã độc) + **benign**; có thể ghép thành một thư mục nhiều lớp để train.
- Có chế độ **synthetic** (byte ngẫu nhiên) chỉ để **chạy thử code**, không nói là đánh giá thực tế.

## 6. Huấn luyện và sau train

- Script **`train_cnn.py`:** đọc ảnh theo thư mục **hoặc** file byte theo lớp → lưu **`malimg_model.keras`** và **`malimg_metadata.json`** (tên lớp khớp thứ tự đầu ra).
- Web load model và với mỗi file upload tính **xác suất** + **top-5** lớp; **P(Benign)** và **1 − P(Benign)** dùng để diễn giải “mức nghi ngờ”, không đồng nghĩa chẩn đoán tuyệt đối.

## 7. Giới hạn (nên nói trong báo cáo)

- Phụ thuộc **chất lượng và lượng** dữ liệu train; có thể **sai** với file lạ hoặc đã chỉnh sửa.
- **Không** thay thế cơ chế chữ ký / chính sách an ninh; mẫu mã độc thật chỉ xử lý trong **môi trường hợp pháp và cách ly**.

## 8. Tham chiếu khoa học / code mẫu

- Malimg (byte → ảnh, phân loại): Nataraj et al., *Malware Images: Visualization and Automatic Classification*.
- Triển khai tham chiếu trong đồ án: [cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN).

---

*Bản tóm tắt này cố ý không đi sâu công thức; khi thầy hỏi chi tiết, mở **`doc-ai-hoc-may.md`**.*

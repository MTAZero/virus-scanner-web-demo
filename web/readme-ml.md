# Học máy trong Virus Scanner (Malimg + CNN)

Tài liệu này mô tả **toàn bộ phần ML** của demo: lý thuyết, dữ liệu, mô hình, huấn luyện, suy luận và cách đọc kết quả trên giao diện. Code tham chiếu repo gốc: [cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN).

---

## 1. Mục tiêu

- Bổ sung một **tầng gợi ý** bằng deep learning bên cạnh quét **chữ ký (ClamAV)**.
- **Không** thay thế antivirus: mô hình có thể nhầm, phụ thuộc dữ liệu train và cách đưa file vào mô hình.

---

## 2. CNN là gì, dùng cho việc gì, vì sao lại hợp với “mã độc dạng ảnh”?

### 2.1. CNN là gì?

**CNN** (Convolutional Neural Network — mạng nơ-ron tích chập) là một kiểu mạng học sâu đặc biệt cho dữ liệu có **cấu trúc lưới** (grid), điển hình là **ảnh**. Ý tưởng cốt lõi: thay vì mỗi pixel nối thẳng vào tầng lớn (như Perceptron cổ điển), CNN dùng **bộ lọc nhỏ** (kernel / filter) **trượt** trên toàn ảnh, cùng một bộ trọng số chia sẻ cho mọi vị trí — nhờ đó học được **mẫu cục bộ** (local patterns) với ít tham số hơn.

Trong code của demo, sau bước Malimg, tensor đầu vào có dạng **(cao, rộng, kênh)** giống ảnh màu → ta áp kiến trúc CNN “chuẩn thị giác máy tính” lên **ma trận byte được tô xám**.

### 2.2. CNN thường dùng để làm gì?

- **Thị giác máy tính:** nhận dạng ảnh, phân loại đôi tượng, phát hiện khuôn mặt, y khoa hình ảnh, v.v.
- **Mọi bài toán có thể coi như “ảnh” hoặc “bản đồ 2D”:** trong bảo mật, người ta **ánh xạ file nhị phân → ma trận 2D** rồi coi đó như một ảnh — CNN liền có “sân chơi” quen thuộc.

Ở dự án này, CNN không đọc hex thủ công hay luật if/else; nó **học từ dữ liệu** các mẫu trực quan trên ảnh hóa Malimg để gợi ý **nhãn lớp** (họ mã độc trong Malimg hoặc Benign).

### 2.3. Các thành phần chính (liên hệ slide / infographic)

| Thành phần | Ý tưởng ngắn gọn | Trong bài Malimg / malware-as-image |
|-------------|------------------|----------------------------------------|
| **Convolution (tích chập)** | Quét **kernel** (cửa sổ nhỏ) trên toàn “ảnh”, nhân chập để nhấn mạnh một số cấu trúc lặp lại. | Phát hiện **cạnh**, chuyển độ thậm chí **pattern byte** cục bộ (vùng ít thay đổi, vùng nhiễu, khối lặp…) vì mỗi “pixel” thực chất là cường độ byte. |
| **ReLU** | Hàm **max(0, x)** — bỏ phần âm, giữ phần dương. | Giúp mạng học **phi tuyến**; tổ hợp nhiều lớp Conv+ReLU cho phép biểu diễn các ranh giới phức tạp giữa các lớp ảnh. |
| **MaxPooling** | Giảm kích thước bản đồ đặc trưng, lấy **giá trị cực đại** trong mỗi ô nhỏ. | **Nén** không gian nhưng vẫn giữ các kích hoạt mạnh — gọn hơn, ít tính toán, có phần **ổn định** nhẹ trước dịch chuyển nhỏ trên lưới. |
| **Fully Connected (FC / Dense)** | Sau các lớp tích chập, vector đặc trưng được nối **fully-connected** tới tầng cuối. | **Quyết định phân loại:** trong demo cuối cùng là **softmax** trên nhiều lớp — tương ứng “file (theo ảnh hóa) gần với họ A, B, … hay Benign”. |

Activation Conv trong demo dùng **ReLU** ngay trong lớp `Conv2D(..., activation='relu')` của chúng ta.

### 2.4. Vì sao CNN lại “hợp” bài toán này (nhưng không phải phép màu)?

**Ưu điểm khi đã có ảnh Malimg:**

1. **Đặc trưng cục bộ:** Mã máy có **cụm lệnh, chuỗi, padding** — trên ảnh hóa chúng thành **vùng sáng/tối, đường ranh**; kernel của CNN được thiết kế đúng để bắt các mẫu cục bộ đó.
2. **Phân cấp:** Lớp Conv sớm có thể bắt pattern nhỏ; lớp sau kết hợp thành pattern lớn hơn — tương tự cách CNN nhận diện đối tượng trong ảnh tự nhiên.
3. **End-to-end:** Không cần kỹ sư tự tay thiết kế hàng trăm đặc trưng thống kê trên file; mạng học từ **nhãn + ảnh** (miễn là dữ liệu đủ và đại diện).

**Giới hạn cần nhớ:**

- CNN chỉ nhìn **biểu diễn Malimg** của file bạn đưa vào, không “hiểu” PE hay EICAR theo nghĩa antivirus.
- Hiệu quả thực tế phụ thuộc **tập train, cân bằng lớp, epoch**, và **cùng pipeline** train/infer (PNG vs byte thô, v.v.).
- **Chữ ký (hash, pattern)** vẫn là lớp phát hiện khác hẳn: nó bật/tắt theo cơ sở dữ liệu đã biết; CNN là **ước lượng thống kê** trên không gian ảnh.

---

## 3. Ý tưởng lý thuyết: vì sao “byte → ảnh”?

Trong nghiên cứu Malimg / malware-as-image:

1. File nhị phân là chuỗi byte. Ta nhóm byte thành lưới (thường **16 byte một hàng**), rồi reshape thành ảnh **xám** (mỗi pixel 0–255).
2. Ảnh này **không phải** ảnh chụp màn hình; nó là **cách nhìn trực quan** lên **cấu trúc bytecode** (các vùng lặp, entropy, v.v.).
3. **CNN** (Convolutional Neural Network) được thiết kế cho ảnh: lớp tích chập học **mẫu cục bộ** (local patterns), phù hợp khi coi ma trận byte như “ảnh”.

Sau bước Malimg, ảnh được **resize** (trong demo: **256×256**) và đưa vào mạng giống pipeline ảnh RGB (thường **nhân 3 kênh** từ ảnh xám để khớp đầu vào 3 kênh như ảnh màu trong huấn luyện).

**Tham khảo:** Nataraj et al., *Malware Images: Visualization and Automatic Classification*; các notebook trong repo cridin1.

---

## 4. Chuỗi xử lý trong code (encoding)

Thư mục `ml/`:

| File | Vai trò |
|------|---------|
| `encoding.py` | Đọc **file bất kỳ** dạng byte → ma trận Malimg (`hex2img` tương đương `data_conversion.ipynb`) → resize → tensor **(256, 256, 3)** float [0, 1]. |
| `class_names.py` | Danh sách **26 lớp** combined (25 họ + `Benign`), thứ tự khớp bài combined_classifier khi dùng đủ lớp. |
| `model_def.py` | Cấu trúc **Sequential** Conv → Pool × 4 → Dropout → Dense → **softmax** (số lớp = `num_classes`). |
| `inference.py` | Nạp `malimg_model.keras` (+ `malimg_metadata.json`), chạy `predict`, trả JSON cho Flask. |
| `malimg_metadata.json` | Do **`train_cnn.py`** ghi: thứ tự `class_names` **phải khớp** thứ tự neuron đầu ra softmax. |

**Lưu ý quan trọng:** Nếu bạn train trên **ảnh PNG** đã có sẵn trong dataset Malimg (file trên đĩa là `.png`), mà inference lại đọc **toàn bộ file** như byte, thì header PNG + cấu trúc file khác với “ảnh Malimg thuần từ PE”. Để so khớp hoàn hảo với ảnh train, cần **cùng một kiểu đặc tả đầu vào** (ví dụ luôn decode PNG như `image_dataset_from_directory`). Demo mặc định dùng **byte file upload** cho thống nhất với luồng “file thật”.

---

## 5. Mô hình (kiến trúc)

Thiết kế bám **`combined_classifier_val.ipynb`** (cridin1):

- **Đầu vào:** `(256, 256, 3)`.
- **Khối:** `Conv2D(64)` → `MaxPool` → `Conv2D(32)` → `MaxPool` → `Conv2D(32)` → `MaxPool` → `Conv2D(16)` → `MaxPool` → `Dropout` → `Flatten` → `Dense(128)` → `Dropout` → `Dense(50)` → `Dropout` → **`Dense(num_classes, softmax)`**.
- **Hàm mất mát:** `categorical_crossentropy`.
- **Đầu ra:** vector xác suất cộng 1 trên **tất cả lớp** (softmax).

`num_classes` = số thư mục lớp khi train (thường **26** nếu dùng đủ Malimg + Benign).

---

## 6. Dữ liệu và thư mục

- **Malimg (25 họ):** ảnh PNG theo từng lớp (ví dụ sau khi tải + giải nén `malimg_dataset.zip`).
- **Benign:** thư mục ảnh sạch (trong demo có thể lấy từ `benign_data/benign_imgs` của repo cridin1).
- **Ghép:** script `datasets/prepare_combined.sh` tạo `datasets/malimg_combined/` — **26** thư mục con (tên lớp = tên folder).

Chi tiết đường dẫn và lệnh tải: `datasets/README.md`.

---

## 7. Cách huấn luyện (`train_cnn.py`)

Chạy trong thư mục **`web/`**:

```bash
cd web
pip install -r requirements.txt
```

### 7.1. Synthetic (nhanh, chỉ để kiểm tra code)

```bash
python train_cnn.py --epochs 8 --samples-per-class 80
```

Tạo byte ngẫu nhiên, gán nhãn 26 lớp cố định; **không** phản ánh độ chính xác thực tế.

### 7.2. Ảnh PNG theo class (khuyến nghị với dataset đã tải)

```bash
python train_cnn.py --malimg-png-root ../datasets/malimg_combined --epochs 10 --batch-size 32
```

`image_dataset_from_directory` tự chia train/val, chuẩn hóa pixel `/255`.

### 7.3. File nhị phân thô theo class

Mỗi lớp là một thư mục chứa file `.exe`/`.dll`/…:

```bash
python train_cnn.py --malimg-bytes-root /path/to/by_class_binaries --epochs 10
```

### Đầu ra

- `ml/malimg_model.keras` — trọng số mô hình.
- `ml/malimg_metadata.json` — danh sách `class_names` theo đúng thứ tự softmax.

Sau khi train, **khởi động lại** Flask để nạp model (hoặc dùng process mới).

---

## 8. Suy luận (inference) và API web

- Endpoint **`POST /upload`:** sau khi quét hash/chữ ký, server gọi `predict_malware_cnn(đường_file)`.
- **`GET /health`:** `ml_model_available`, `ml_model_path`.

### Ý nghĩa các trường JSON (`mode: malimg_cridin1`)

| Trường | Ý nghĩa |
|--------|---------|
| `predicted_class` | Lớp có xác suất **cao nhất** (top-1). |
| `probabilities_top5` | 5 lớp có xác suất cao nhất; với 26 lớp, từng phần trăm thường **không lớn** vì xác suất bị **chia mỏng**. |
| `benign_probability` | Xác suất mô hình gán vào lớp **Benign**. |
| `malware_probability` | Trong code hiện tại ≈ **1 − P(Benign)** — dùng làm “độ lệch khỏi sạch”, **không** tương đương “xác suất đúng là họ X”. |
| `is_benign_prediction` | `true` nếu top-1 là `Benign`. |

Nếu còn model cũ **một neuron sigmoid** (`malware_cnn.keras`), `mode` sẽ là `legacy_binary` (nhị phân).

---

## 9. Đọc giao diện web (module ML)

Giao diện được viết lại theo hướng **dễ hiểu**:

- **Tiêu đề:** gợi ý từ học máy, nhấn mạnh không thay thế quét chữ ký.
- **Kết luận nhanh:** badge xanh / cam / đỏ theo mức nghi ngờ.
- **Dòng “Độ tin là file sạch”:** trực tiếp **P(Benign)**.
- **Thanh màu:** “Mức nghi ngờ (càng cao = mô hình càng ít tin là sạch)”.
- **Bảng 5 dòng:** “Các lớp mô hình còn đang phân vân” — tránh hiểu nhầm một % nhỏ là “chắc chắn đúng họ đó”.

---

## 10. Hạn chế và khuyến nghị

1. **Chất lượng phụ thuộc train:** cần đủ epoch, dữ liệu cân bằng hoặc xử lý mất cân bằng (class weights, v.v.) nếu báo cáo yêu cầu.
2. **Đầu vào phải nhất quán:** train trên PNG Malimg thì cần rõ pipeline inference có cùng kiểu biểu diễn hay không.
3. **Không dùng một mình CNN** cho quyết định an ninh: luôn kết hợp chữ ký, sandbox, chính sách tổ chức.

---

## 11. Tóm tắt một dòng

**Byte → ảnh Malimg → CNN + softmax → phân phối xác suất trên nhiều lớp (gồm Benign); UI diễn giải “sạch vs nghi ngờ” và top-5 lớp để người xem không nhầm % softmax với “độ chắc chắn tuyệt đối”.**

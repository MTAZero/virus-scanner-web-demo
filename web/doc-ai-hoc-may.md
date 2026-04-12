# Trí tuệ nhân tạo và học máy trong mã nguồn Virus Scanner

Tài liệu này mô tả **toàn bộ** phần liên quan đến **AI / học sâu (deep learning)** trong project: nền lý thuyết (giải thích chi tiết), kỹ thuật cụ thể trong code, dữ liệu, luồng huấn luyện–suy luận, và giới hạn. Phần chữ ký (hash, Aho–Corasick trên `virus_signatures.txt`) **không phải AI**; chỉ phần thư mục `web/ml/` và `web/train_cnn.py` cộng tích hợp trong `app.py` thuộc nhóm này.

- **`readme-ml.md`:** hướng dẫn thao tác ngắn gọn.
- **`doc-ai-bao-cao-tom-tat.md`:** bản **khái quát nhất** (đủ ý cho báo cáo thầy), không đi sâu công thức.
- **File này (`doc-ai-hoc-may.md`):** đọc thêm khi cần hiểu chi tiết lý thuyết và khớp với code.

---

## Mục lục

1. [Phạm vi: AI trong repo này là gì?](#1-phạm-vi-ai-trong-repo-này-là-gì)
2. [Nền tảng: học máy có giám sát và học sâu](#2-nền-tảng-học-máy-có-giám-sát-và-học-sâu) — trong đó **2.1a** (mạng nơ-ron), **2.1b** (bản chất huấn luyện)
3. [Mạng nơ-ron tích chập (CNN): lý thuyết mở rộng](#3-mạng-nơ-ron-tích-chập-cnn-lý-thuyết-mở-rộng)
4. [Bài toán “mã độc dạng ảnh” (Malimg / malware-as-image)](#4-bài-toán-mã-độc-dạng-ảnh-malimg--malware-as-image)
5. [Kỹ thuật trong code: biểu diễn dữ liệu (`encoding.py`)](#5-kỹ-thuật-trong-code-biểu-diễn-dữ-liệu-encodingpy)
6. [Kiến trúc mô hình (`model_def.py`)](#6-kiến-trúc-mô-hình-model_defpy)
7. [Dữ liệu: nguồn, định dạng, cách ghép](#7-dữ-liệu-nguồn-định-dạng-cách-ghép)
8. [Huấn luyện (`train_cnn.py`)](#8-huấn-luyện-train_cnnpy)
9. [Suy luận và metadata (`inference.py`, `malimg_metadata.json`)](#9-suy-luận-và-metadata-inferencepy-malimg_metadatajson)
10. [Tích hợp web (`app.py`, giao diện)](#10-tích-hợp-web-apppy-giao-diện)
11. [Phân loại lớp (`class_names.py`)](#11-phân-loại-lớp-class_namespy)
12. [Thư viện và phiên bản](#12-thư-viện-và-phiên-bản)
13. [Giới hạn, đạo đức và cách báo cáo](#13-giới-hạn-đạo-đức-và-cách-báo-cáo)
14. [Tham chiếu](#14-tham-chiếu)

---

## 1. Phạm vi: AI trong repo này là gì?

| Thành phần | Có dùng AI? | Ghi chú |
|------------|-------------|---------|
| Quét MD5/SHA256, khớp chữ ký hex (ClamAV-style) | **Không** | So khớp từ điển + tìm mẫu; quy tắc rõ ràng, không học từ dữ liệu. |
| **`ml/` + TensorFlow/Keras** | **Có** | Mạng CNN học **tham số** từ dữ liệu ảnh hóa file (Malimg). |
| **`train_cnn.py`** | **Có** | Huấn luyện / fine-tune CNN. |

**Vai trò định vị:** CNN chỉ là **gợi ý thống kê** (xác suất trên các lớp đã định nghĩa khi train). Nó **không** thay thế antivirus chữ ký và **không** “hiểu” ngữ nghĩa PE hay luật an ninh.

---

## 2. Nền tảng: học máy có giám sát và học sâu

### 2.1. Học có giám sát (supervised learning)

Ta có tập mẫu \(\{(x_i, y_i)\}\), trong đó \(x_i\) là **đầu vào** (ở đây là tensor ảnh \(256\times256\times3\)) và \(y_i\) là **nhãn** (một trong \(K\) lớp, ví dụ họ mã độc Malimg hoặc `Benign`).

Mục tiêu: học một hàm \(f_\theta\) (mạng nơ-ron với tham số \(\theta\)) sao cho \(f_\theta(x)\) **gần** với nhãn thật. Đo “gần” bằng **hàm mất mát** (loss).

### 2.1a. Mạng nơ-ron nhân tạo (ANN): bản chất cấu trúc

**Nơ-ron (perceptron / nơ-ron tổng quát).** Một nơ-ron nhận vector đầu vào \(x\), nhân với **trọng số** \(w\), cộng **hệ số đệm** (bias) \(b\), rồi đưa qua **hàm kích hoạt** \(\sigma\): \(a = \sigma(w^\top x + b)\). Hàm \(\sigma\) thường **phi tuyến** (ReLU, sigmoid, …) — nếu không có bước phi tuyến, chồng nhiều lớp tuyến tính vẫn chỉ tương đương **một** phép biến đổi tuyến tính.

**Lớp (layer).** Nhiều nơ-ron song song tạo một **lớp ẩn** hoặc **lớp đầu ra**: mỗi nơ-ron có bộ trọng riêng; đầu ra của lớp trước là đầu vào của lớp sau. **Mạng feedforward** (như CNN + Dense trong project) chỉ có luồng **một chiều** từ đầu vào tới đầu ra, không có vòng phản hồi nội bộ trong một lần suy luận.

**Forward pass (lan truyền xuôi).** Với đầu vào \(x\), mạng tính lần lượt các lớp từ đầu đến cuối để ra dự đoán \(\hat{y} = f_\theta(x)\). Toàn bộ phép tính là **có thể vi phân** (gần như mọi chỗ) để sau đó lấy **đạo hàm** của loss theo \(\theta\).

**Tham số \(\theta\).** Gồm tất cả trọng số và bias (trong Conv: trọng số của từng kernel; trong Dense: ma trận nối giữa hai vector). **Huấn luyện** nghĩa là **tìm** giá trị \(\theta\) sao cho loss trung bình trên tập mẫu nhỏ — không phải “lập trình tay” từng trọng số.

### 2.1b. Bản chất khi huấn luyện: loss, lan truyền ngược, cập nhật

**Loss (hàm mất mát).** Gán một số thực không âm đo **sai lệch** giữa dự đoán \(\hat{y}\) và nhãn \(y\) (ví dụ cross-entropy cho phân loại softmax). Loss **càng nhỏ** thì (trên tập train) mô hình càng khớp nhãn — nhưng khớp quá mức có thể là **overfit**.

**Gradient.** Đạo hàm \(\nabla_\theta L\) chỉ hướng và độ lớn **thay đổi cục bộ** của \(L\) theo từng thành phần của \(\theta\). Ý tưởng hạ gradient: đi một bước ngược hướng gradient để giảm \(L\) (trong miền lân cận).

**Lan truyền ngược (backpropagation).** Không tính tay đạo hàm từng trọng số; thuật toán **chuỗi** (quy tắc chuỗi / tích đạo hàm) tính gradient **từ lớp cuối về lớp đầu** một cách có hệ thống. Độ phức tạp tương đương vài lần forward pass — nhờ đó mạng có **hàng triệu** tham số vẫn huấn luyện được.

**Bản chất vòng lặp huấn luyện.** (1) Lấy một **mini-batch** mẫu. (2) **Forward** tính \(\hat{y}\) và \(L\). (3) **Backward** tính \(\nabla_\theta L\). (4) **Cập nhật** \(\theta\) (Adam, SGD, …). (5) Lặp qua nhiều batch và nhiều **epoch** cho đến khi loss/validation ổn định hoặc hết epoch. Kết quả: \(\theta\) **không** phải nghiệm tối ưu toàn cục tổng quát — thường là **cực tiểu cục bộ** hoặc điểm đủ tốt; vẫn đủ để mô hình **khái quát** một phần lên dữ liệu mới nếu dữ liệu và kiến trúc phù hợp.

**Liên hệ project.** `model.fit` trong TensorFlow/Keras ẩn toàn bộ vòng (forward → loss → backward → Adam). File `model_def.py` chỉ **khai báo kiến trúc** và `compile`; **bản chất học** nằm ở quá trình này, không ở một dòng lệnh “học” riêng.

### 2.2. Học sâu (deep learning)

**“Sâu” nghĩa là gì.** Trong ngữ cảnh này, **học sâu** không phải một thuật toán riêng mà chỉ **cách xây mô hình**: chuỗi **nhiều lần biến đổi** liên tiếp \(x \mapsto h^{(1)} \mapsto h^{(2)} \mapsto \cdots \mapsto h^{(L)}\), mỗi bước là một lớp mạng (Conv, Dense, v.v.) kèm **hàm kích hoạt phi tuyến** (ReLU, softmax ở cuối). Số lớp \(L\) lớn (thường từ vài chục đến hàng trăm “lớp tính toán” trong kiến trúc lớn) là lý do gọi là *deep*; mô hình **nông** (*shallow*) thường chỉ có một hoặc rất ít lớp ánh xạ từ đầu vào sang nhãn.

**Vì sao phải xếp nhiều lớp và phi tuyến.** Nếu chỉ nhân ma trận liên tiếp **không** có phi tuyến ở giữa, toàn bộ tương đương **một** phép biến đổi tuyến tính — không thể tách được các ranh giới phức tạp giữa nhiều lớp dữ liệu. Các hàm như ReLU (\(\max(0,x)\)) phá tính tuyến tính, cho phép **tổ hợp** nhiều lớp tạo ra các vùng quyết định phi tuyến rất linh hoạt (ý tưởng gần với định lý xấp xỉ phổ quát: mạng đủ rộng/sâu có thể xấp xỉ hàm mượt trong miền compact, với điều kiện thích hợp).

**Phân cấp đặc trưng (hierarchical features).** Trong CNN, các lớp **gần đầu vào** thường trở nên nhạy với **mẫu cục bộ đơn giản** (cạnh, chuyển độ độ sáng, texture thô trên “ảnh” Malimg); các lớp **sâu hơn** kết hợp các mẫu đó thành **cấu trúc lớn hơn** (vùng đồng nhất, họa tiết lặp, ranh giới giữa các khối byte, v.v.). Các vector ở tầng gần cuối có thể xem là **mã hóa** (embedding) của toàn file sau khi đã qua nhiều phép trích xuất — không cần người định nghĩa thủ công “entropy toàn file”, “histogram opcode”, v.v.; mạng **học** cách dùng thông tin thô để giảm loss trên tập nhãn.

**So với pipeline cổ điển.** Cách truyền thống: kỹ sư thiết kế **đặc trưng tay** (thống kê byte, entropy, chuỗi n-gram, v.v.) rồi đưa vào SVM, rừng ngẫu nhiên, v.v. **Học sâu end-to-end** (ở đây: tensor Malimg → CNN → softmax) gom **trích đặc trưng** và **phân loại** trong **một** mạng được huấn luyện chung; gradient chảy ngược từ loss đến cả kernel Conv lẫn tầng Dense, nên các bộ lọc đầu tiên được điều chỉnh để phục vụ trực tiếp bài toán nhãn.

**Liên hệ trực tiếp với mã nguồn.** Trong `model_def.py`, chuỗi **Conv2D + MaxPool** lặp lại nhiều lần rồi **Flatten → Dense → Dropout → Dense → softmax** chính là một mạng **sâu** theo nghĩa trên: đầu vào là ảnh Malimg đã chuẩn hóa, đầu ra là xác suất trên \(K\) lớp; toàn bộ trọng số giữa đó được học từ dữ liệu qua `train_cnn.py`, không qua một bước trích đặc trưng tách rời.

**Giới hạn cần nhớ (không chỉ “càng sâu càng tốt”).** Mạng sâu cần **nhiều dữ liệu**, dễ **quá khớp** (overfit) nếu tập train nhỏ hoặc lặp lại — trong code có **Dropout** và tách **validation** để giảm rủi ro đó; chất lượng tổng quát vẫn phụ thuộc phân phối dữ liệu và đánh giá ngoài tập train.

### 2.3. Tối ưu hóa (gradient, mini-batch, Adam)

**Mục tiêu số học.** Huấn luyện là tìm \(\theta\) sao cho **trung bình** hàm mất mát trên tập mẫu (empirical risk) nhỏ nhất. Với mạng sâu, không có công thức đóng để “giải một bước”; người ta dùng **hạ gradient lặp**: từ \(\theta\) hiện tại, tính **gradient** \(\nabla_\theta L\) (đạo hàm của loss theo từng trọng số) rồi dịch \(\theta\) theo hướng làm \(L\) giảm nhanh nhất cục bộ.

**Mini-batch.** Thay vì mỗi bước dùng **toàn bộ** tập train (batch đầy — tính gradient chính xác nhưng rất chậm và tốn bộ nhớ), `train_cnn.py` thường dùng **`model.fit(..., batch_size=32)`** hoặc `Dataset` với batch cố định: mỗi bước chỉ tính gradient trên **một lô nhỏ** mẫu (ví dụ 32 ảnh). Gradient đó là **ước lượng nhiễu** của gradient toàn tập, nhưng mỗi epoch vẫn “nhìn” đủ dữ liệu qua nhiều bước; đổi lại huấn luyện nhanh và thực tế hơn trên GPU/CPU.

**Adam là gì (trong project dùng mặc định của Keras).** **Adam** (*Adaptive Moment Estimation*) không chỉ đi một bước cố định theo \(-\nabla L\) như SGD thuần. Nó duy trì hai thống kê trượt theo thời gian trên **từng tham số** \(\theta_j\):

- **Moment bậc một** \(m\): trung bình động của gradient (giống **momentum**) — làm bước cập nhật “có quán tính”, giảm dao động khi bề mặt loss gồ ghề.
- **Moment bậc hai** \(v\): trung bình động của **bình phương** gradient (tương tự **RMSprop**) — cho phép **tỷ lệ bước khác nhau** cho từng trọng số: tham số có gradient lớn/ổn định được điều chỉnh khác tham số có gradient nhỏ hoặc thưa.

Keras còn áp **hiệu chỉnh bias** cho \(m, v\) ở các bước đầu và dùng siêu tham số mặc định (learning rate, \(\beta_1\), \(\beta_2\), \(\epsilon\)) — bạn không cần khai báo trong `model_def.py` vì đã gọi `compile(..., optimizer="adam")`.

**Liên hệ trực tiếp với code.** Mỗi lần `model.fit` chạy một **epoch**, TensorFlow lặp qua các mini-batch, tính `categorical_crossentropy`, **backpropagation** tính \(\nabla_\theta L\), rồi **Adam** cập nhật toàn bộ trọng số CNN. Không có đoạn “tối ưu tay” trong repo — toàn bộ là tự động qua API Keras.

### 2.4. Phân loại đa lớp và xác suất

Đầu ra mong muốn là **phân phối xác suất** trên \(K\) lớp: \(p_k \ge 0\), \(\sum_k p_k = 1\). Tầng cuối dùng **softmax** biến \(K\) số thực (logit) thành vector xác suất. Nhãn huấn luyện được mã hóa **one-hot** (vector chỉ một chiều bằng 1) — trong code dùng `label_mode="categorical"` hoặc `np.eye`.

**Hàm mất mát:** `categorical_crossentropy` — tương đương **cực đại hóa xác suất** gán cho đúng lớp (cross-entropy giữa phân phối one-hot và softmax).

---

## 3. Mạng nơ-ron tích chập (CNN): lý thuyết mở rộng

### 3.1. Vì sao cần CNN cho dữ liệu dạng ảnh?

Ảnh (và “ảnh” Malimg) có **tương quan không gian**: pixel lân cận thường liên quan. **Tích chập** dùng **một bộ lọc (kernel)** nhỏ trượt trên toàn bản đồ, **chia sẻ trọng số** ở mọi vị trí → ít tham số hơn fully-connected đầy đủ trên toàn ảnh, và phù hợp với **mẫu cục bộ** (cạnh, khối, texture).

### 3.2. Convolution + ReLU

- **Conv2D:** với mỗi vị trí, tính tổng có trọng số trên một cửa sổ nhỏ (ví dụ \(3\times3\)) trên tất cả kênh đầu vào (ở đây 3 kênh nhưng giá trị nhân bản từ xám nên có tương quan đặc biệt).
- **ReLU** \(\max(0,x)\): tạo **phi tuyến**, cho phép tổ hợp nhiều lớp biểu diễn ranh giới phức tạp.

### 3.3. Max-pooling

Giảm kích thước không gian (ví dụ lấy max trong ô \(2\times2\)): **giảm chi phí tính**, tăng **vùng thụ cảm** (receptive field) của lớp sau, có tác dụng **ổn định nhẹ** trước dịch chuyển nhỏ trên lưới.

### 3.4. Flatten và Dense

Sau các lớp conv/pool, tensor 3D được **duỗi** thành vector (**Flatten**), rồi qua các **Dense (fully connected)** để kết hợp đặc trưng toàn cục trước khi ra softmax.

### 3.5. Dropout

**Dropout** tắt ngẫu nhiên một phần nơ-ron khi train → giảm **coadaptation** (phụ thuộc lẫn nhau quá mức), giúp **khái quát hóa** tốt hơn lên dữ liệu chưa thấy. Khi suy luận, dropout không tắt nơ-ron theo kiểu train (Keras tự scale).

### 3.6. Softmax và cách đọc kết quả

Softmax làm cho các logit thành xác suất. **Chú ý quan trọng:** với \(K\) lớp lớn, mỗi \(p_k\) thường **nhỏ**; top-1 **không** đồng nghĩa “chắc chắn 100% đúng họ đó” — đó chỉ là **ước lượng mô hình** trên biểu diễn Malimg, có thể sai với file ngoài phân phối train (OOD).

---

## 4. Bài toán “mã độc dạng ảnh” (Malimg / malware-as-image)

### 4.1. Ý tưởng nghiên cứu

Thay vì chỉ dùng đặc trưng thủ công trên file, người ta **chuyển chuỗi byte** thành ma trận 2D, coi như **ảnh xám**: mỗi byte (0–255) là cường độ pixel. Các vùng **entropy**, **lặp**, **cấu trúc** của binary có thể tạo **họa tiết** khác nhau giữa họ mã độc — CNN có thể học các pattern trực quan đó (trong giới hạn dữ liệu và pipeline).

Tham khảo ý tưởng: Nataraj et al., *Malware Images: Visualization and Automatic Classification*; triển khai notebook trong repo [cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN).

### 4.2. Liên hệ với “AI” rộng hơn

Đây là **học sâu có giám sát** cổ điển, **không** dùng LLM, **không** reinforcement learning trong code hiện tại. “AI” trong báo cáo thường chỉ **mô hình CNN học được từ dữ liệu**.

---

## 5. Kỹ thuật trong code: biểu diễn dữ liệu (`encoding.py`)

### 5.1. Chuỗi xử lý

1. Đọc toàn bộ (hoặc một phần) file dạng **`bytes`**.
2. **Padding** độ dài chia hết cho **16** (mỗi hàng 16 byte — đúng convention Malimg/hex2img trong repo gốc).
3. Reshape thành ma trận \((N_{\text{row}}, 16)\).
4. **`_hex2img_mat`:** gom thành ảnh xám 2D kích thước \((a, b)\) theo logic **lũy thừa 2** (bậc \(b\) được chọn từ \(\sqrt{N_{\text{byte}}}\) như trong notebook gốc) — **không** phải chỉ reshape tùy ý một hình chữ nhật cố định trước bước này.
5. **Resize** ảnh xám lên **256×256** bằng **LANCZOS** (PIL) — mượt, phù hợp thu nhỏ/phóng to biểu diễn.
6. Chuẩn hóa pixel \(\in [0,1]\), **nhân bản** thành **3 kênh** giống ảnh RGB (`stack` cùng một kênh xám 3 lần) để khớp đầu vào CNN huấn luyện trên ảnh 3 kênh.

### 5.3. Legacy (model cũ)

`file_to_legacy_rgb_tensor`: đọc **64×64×3** byte đầu, reshape trực tiếp — dùng khi còn file `malware_cnn.keras` **một đầu ra sigmoid** (nhị phân), không phải pipeline Malimg đầy đủ.

### 5.4. Nhất quán train / infer

- Nếu train trên **PNG** đã render sẵn (`image_dataset_from_directory`), inference trên **file upload** (byte → Malimg) có thể **khác phân phối** so với PNG (header file, v.v.). Tài liệu `readme-ml.md` đã cảnh báo: nên thống nhất đặc tả đầu vào khi cần độ chính xác cao.

---

## 6. Kiến trúc mô hình (`model_def.py`)

Hàm `build_malware_model_cridin1(num_classes, img_size=256)` xây **`keras.Sequential`**:

| Thứ tự | Lớp | Vai trò ngắn gọn |
|--------|-----|------------------|
| 1 | `Input((256,256,3))` | Khai báo kích thước đầu vào |
| 2–3 | `Conv2D(64, 3×3, relu)` → `MaxPool 2×2` | Đặc trưng cấp thấp |
| 4–5 | `Conv2D(32, …)` → `MaxPool` | Đặc trưng trung gian |
| 6–7 | `Conv2D(32, …)` → `MaxPool` | Tiếp tục trích xuất |
| 8–9 | `Conv2D(16, …)` → `MaxPool` | Sâu hơn, bản đồ nhỏ hơn |
| 10 | `Dropout(0.25)` | Giảm overfit |
| 11 | `Flatten` | Vector hóa |
| 12–13 | `Dense(128, relu)` + `Dropout(0.25)` | Kết hợp đặc trưng |
| 14–15 | `Dense(50, relu)` + `Dropout(0.5)` | Rút gọn trước lớp cuối |
| 16 | `Dense(num_classes, softmax)` | Phân phối xác suất trên \(K\) lớp |

**Biên dịch:** `optimizer="adam"`, `loss="categorical_crossentropy"`, `metrics=["accuracy"]`.

**`num_classes`:** bằng số thư mục lớp khi train (thường **26** nếu đủ Malimg 25 họ + Benign).

---

## 7. Dữ liệu: nguồn, định dạng, cách ghép

### 7.1. Bộ Malimg (25 họ mã độc)

Ảnh PNG theo từng lớp (tên thư mục = tên họ). Thường lấy từ dataset kiểu `malimg_dataset` (sau giải nén). Chi tiết đường dẫn: **`datasets/README.md`** trong repo.

### 7.2. Benign

Ảnh / mẫu “sạch” để có lớp **Benign** trong bài toán đa lớp (ví dụ thư mục benign trong workflow cridin1).

### 7.3. Ghép 26 lớp

Script **`datasets/prepare_combined.sh`** tạo cấu trúc **`datasets/malimg_combined/`**: mỗi thư mục con là một **tên lớp** (25 họ + Benign), bên trong là ảnh hoặc file tùy pipeline train.

### 7.4. Dữ liệu tổng hợp nhân tạo (synthetic)

`train_cnn.py` có thể tạo **byte ngẫu nhiên**, gán nhãn theo `MALIMG_COMBINED_CLASSES`, rồi áp `bytes_to_malimg_tensor`. Mục đích: **kiểm tra code**, **không** phản ánh độ chính xác thực tế trên mã độc thật.

---

## 8. Huấn luyện (`train_cnn.py`)

### 8.1. Ba chế độ

| Chế độ | Cờ | Đầu vào | Ghi chú |
|--------|-----|---------|---------|
| Synthetic | (mặc định nếu không chỉ PNG/bytes) | Byte random → Malimg | Nhanh, chỉ để debug |
| PNG theo lớp | `--malimg-png-root` | Thư mục gốc, mỗi subfolder = một lớp | `image_dataset_from_directory`, chia 80/20 train/val, rescale `/255` |
| Byte thô theo lớp | `--malimg-bytes-root` | Mỗi subfolder chứa file nhị phân | `file_to_malimg_tensor` từng file, shuffle + split 85/15 |

### 8.2. Siêu tham số thường gặp

- `--epochs`, `--batch-size`, `--img-size` (mặc định 256), `--seed` (tái lập chia dữ liệu).

### 8.3. Đầu ra

- **`web/ml/malimg_model.keras`:** mô hình đã train.
- **`web/ml/malimg_metadata.json`:** JSON chứa **`class_names`** — **thứ tự phải trùng** thứ tự neuron softmax (quan trọng khi đặt tên lớp và khi đọc `predicted_class`).

---

## 9. Suy luận và metadata (`inference.py`, `malimg_metadata.json`)

### 9.1. Chọn model

- Ưu tiên **`malimg_model.keras`** (`MODEL_PRIMARY`).
- Nếu không có, thử **`malware_cnn.keras`** (`MODEL_LEGACY`) — nhận diện qua `model.output_shape[-1] == 1` (sigmoid nhị phân).

### 9.2. Đa lớp (softmax)

- Đọc file → `file_to_malimg_tensor` (kích thước lấy từ `model.input_shape`).
- `model.predict` → vector xác suất.
- Ánh xạ chỉ số → tên lớp từ `malimg_metadata.json` hoặc fallback `MALIMG_COMBINED_CLASSES`.
- **`benign_probability`:** xác suất tại lớp `Benign` (tìm theo tên hoặc index cố định).
- **`malware_probability` trong code:** \(\approx 1 - P(\text{Benign})\) — diễn giải là **mức “không-sạch” theo mô hình**, không phải xác suất “đúng họ X” theo nghĩa khoa học pháp y.
- **Top-5:** năm lớp có xác suất cao nhất — giúp thấy **độ không chắc chắn** khi nhiều lớp có % thấp và gần nhau.

### 9.3. Legacy nhị phân

Một số đầu ra `sigmoid`: `malware_probability` trực tiếp, nhãn `malware`/`benign` theo ngưỡng.

---

## 10. Tích hợp web (`app.py`, giao diện)

- Sau khi quét hash và pattern, nếu import được `predict_malware_cnn`, server gọi **`predict_malware_cnn(đường_dẫn_file)`** và gắn kết quả vào **`results['ml']`**.
- **`GET /health`:** báo model có sẵn không (`MODEL_PRIMARY` / `MODEL_LEGACY`).
- Giao diện (`templates/`, `static/js/main.js`): hiển thị verdict, \(P(\text{Benign})\), thanh “mức nghi ngờ”, top-5 — xem **`readme-ml.md`** mục giao diện.

---

## 11. Phân loại lớp (`class_names.py`)

Tuple **`MALIMG_COMBINED_CLASSES`:** 26 tên lớp theo thứ tự **combined_classifier** của cridin1 (index **6** = `Benign`). Dùng khi không có metadata hoặc để đồng bộ tài liệu.

---

## 12. Thư viện và phiên bản

- **TensorFlow / Keras:** huấn luyện và suy luận (trong `requirements.txt` có dải phiên bản TF đã kiểm tra).
- **NumPy:** tensor, buffer byte.
- **Pillow (PIL):** resize ảnh Malimg.

---

## 13. Giới hạn, đạo đức và cách báo cáo

1. **Chất lượng** phụ thuộc tập train, cân bằng lớp, số epoch, và khớp pipeline đầu vào.
2. **Hash / chữ ký** và **CNN** bổ trợ nhau: kết quả CNN không nên được trình bày như “phát hiện chắc chắn” khi không có đánh giá độc lập trên tập test đại diện.
3. **Mẫu thật** (mã độc) chỉ dùng trong môi trường **cách ly**, tuân thủ **pháp luật** và quy định tổ chức.
4. Trong báo cáo học thuật, nên nêu rõ: kiến trúc tham chiếu (cridin1), Malimg, framework (TensorFlow), và phân biệt **kết quả demo** với **đánh giá định lượng** (accuracy/F1 trên tập giữ riêng, v.v.) nếu có.

---

## 14. Tham chiếu

- Repo huấn luyện tham chiếu: [cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN)
- Bài Malimg gốc: Nataraj et al., *Malware Images: Visualization and Automatic Classification*
- Hướng dẫn vận hành ngắn trong project: **`readme-ml.md`**
- Dataset và script chuẩn bị dữ liệu: **`datasets/README.md`**

---

*Tài liệu này phản ánh trạng thái mã nguồn tại thời điểm tạo file. Nếu `model_def.py` hoặc `inference.py` thay đổi, cần cập nhật các mục tương ứng.*

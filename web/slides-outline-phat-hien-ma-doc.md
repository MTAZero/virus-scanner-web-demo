# Outline trình chiếu — Phát hiện mã độc & Mustang Panda

File này dùng để nhờ AI/tool khác dựng slide (PPTX/Google Slides).  
**Đã bỏ** slide riêng về thống kê commit / số dòng trong `virus_signatures.txt`.  
Còn **9 slide** (1 tiêu đề + 8 nội dung).

---

## Slide 1 — Tiêu đề

**Tiêu đề slide:** Phát hiện mã độc: lý thuyết và thực hành  

**Phụ đề:** Bổ sung dữ liệu Mustang Panda (APT) vào tầng chữ ký — đồ án scanner  

**Ghi chú người thuyết trình:**  
Chào khán giả: trình bày đi từ lý thuyết các lớp phát hiện, sang kiến trúc demo (chữ ký ClamAV + CNN Malimg), có đoạn bối cảnh Mustang Panda và insight mẫu — không đi sâu thống kê commit hay số dòng trong DB. Nhấn mạnh: CNN là gợi ý, chữ ký là khớp mẫu đã biết.

---

## Slide 2 — Mục tiêu & vấn đề

**Tiêu đề slide:** Mục tiêu & vấn đề  

**Gạch đầu dòng:**

- Mã độc đa dạng: packer, biến thể, chiến dịch APT có mồi nhử tinh vi  
- Không có một phương pháp duy nhất: cần nhiều lớp (signature, heuristic, ML…)  
- Đồ án: minh họa hybrid — quét chữ ký + gợi ý CNN trên ảnh hóa byte  

**Ghi chú người thuyết trình:**  
Giải thích ngắn tại sao chỉ dựa vào một kỹ thuật là không đủ. Zero-day và mẫu chỉnh sửa nhẹ có thể lọt hash; pattern có thể false positive nếu quá ngắn; ML có thể nhầm nếu dữ liệu train lệch. Slide này dẫn dắt sang phân loại các hướng tiếp cận ở slide sau.

---

## Slide 3 — Ba hướng phát hiện (tổng quan lý thuyết)

**Tiêu đề slide:** Ba hướng phát hiện (tổng quan lý thuyết)  

**Gạch đầu dòng:**

- Chữ ký / tri thức: hash, IOC, mẫu byte, rules (ClamAV, YARA…)  
- Heuristic & hành vi: sandbox, API monitoring, anomaly trên host/network  
- Học máy: đặc trưng học từ dữ liệu (ví dụ Malimg + CNN) — xác suất, không phải luật cứng  

**Ghi chú người thuyết trình:**  
Khi trả lời thầy: chữ ký giải thích được (đã biết mẫu); hành vi cần môi trường quan sát; ML là thống kê trên không gian đặc trưng. Trong thực tế enterprise thường xếp chồng: EDR + AV + threat intel + (đôi khi) ML.

---

## Slide 4 — Chữ ký: hash, mẫu byte & quét nhanh

**Tiêu đề slide:** Chữ ký: hash, mẫu byte & quét nhanh  

**Gạch đầu dòng:**

- Hash: khớp tức thì nếu trùng — yếu với biến thể chưa có trong DB  
- Mẫu byte / wildcard: linh hoạt hơn, cần thiết kế và cập nhật DB  
- Nhiều mẫu → dùng automaton đa mẫu (Aho–Corasick) khi quét buffer  

**Ghi chú người thuyết trình:**  
Liên hệ code: khi chạy app có log load signature và build Aho–Corasick — đó là tối ưu để quét hàng trăm nghìn pattern không duyệt naive từng rule một. Nhắc trade-off: pattern quá chung có thể FP.

---

## Slide 5 — Học máy: Malimg + CNN (lớp gợi ý)

**Tiêu đề slide:** Học máy: Malimg + CNN (lớp gợi ý)  

**Gạch đầu dòng:**

- Byte → lưới 2D (Malimg) → resize — coi như ảnh để vào CNN  
- Conv / Pool: mẫu cục bộ; Dense + softmax: phân loại đa lớp  
- Vai trò trong đồ án: tham khảo xác suất — không thay thế antivirus  

**Ghi chú người thuyết trình:**  
Trích ý từ readme-ml và doc-ai-bao-cao-tom-tat: CNN học trên biểu diễn ảnh của file, không đọc cấu trúc PE như phân tích tĩnh chuyên sâu. Nên nói rõ giới hạn: file lạ, adversarial padding, hoặc lớp không có trong train.

---

## Slide 6 — Kiến trúc demo: hai lớp bổ sung nhau

**Tiêu đề slide:** Kiến trúc demo: hai lớp bổ sung nhau  

**Gạch đầu dòng:**

- Upload file → quét chữ ký (hash + pattern từ DB)  
- Song song / kế tiếp: CNN trên ảnh hóa → top lớp + mức nghi ngờ  
- Kết quả: kết hợp diễn giải — khớp signature vs gợi ý thống kê  

**Ghi chú người thuyết trình:**  
Đây là slide sơ đồ khái niệm: có thể vẽ thêm mũi tên trên PPT. Thông điệp chính: signature cho IOC đã biết; CNN cho tín hiệu khi chưa có rule hoặc cần ưu tiên phân tích. Nếu thầy hỏi "tại sao không chỉ ML": độ giải thích và độ tin cậy khác nhau.

---

## Slide 7 — Mustang Panda (APT): bối cảnh

**Tiêu đề slide:** Mustang Panda (APT): bối cảnh  

**Gạch đầu dòng:**

- Nhóm APT được gán nhiều tên theo báo cáo (RedDelta, Bronze President…)  
- Thường: spear-phishing, mồi nhử tài liệu, công cụ tùy biến, DLL side-load  
- Mục tiêu trình bày: nêu vì sao cần bổ sung IOC/hash vào DB nội bộ  

**Ghi chú người thuyết trình:**  
Trình bày trung lập: dựa trên báo cáo công khai và mẫu thu thập trong phạm vi nghiên cứu. Không cần đi sâu attribution chính trị — tập trung kỹ thuật: vector ban đầu, persistence, TTPs nếu có thời gian.

---

## Slide 8 — Insight từ mẫu & ý nghĩa với scanner

**Tiêu đề slide:** Insight từ mẫu & ý nghĩa với scanner  

**Gạch đầu dòng:**

- Tên artifact thường giả mạo phần mềm quen thuộc — dấu hiệu mồi nhử  
- Nhiều .dll/.dat đi kèm — gợi ý side-loading / đóng gói lẫn binary hợp pháp  
- CNN có thể không có lớp Mustang Panda riêng → tầng chữ ký đóng vai trò then chốt cho các hash này  

**Ghi chú người thuyết trình:**  
Nhấn mạnh đạo đức: chỉ demo trong lab cách ly; không phát tán mẫu. Về mặt kỹ thuật: khi file trùng hash trong DB, scanner báo theo tên trong DB; CNN vẫn có thể đưa ra phân loại Malimg khác.

---

## Slide 9 — Kết luận & tham chiếu

**Tiêu đề slide:** Kết luận & tham chiếu  

**Gạch đầu dòng:**

- Tóm tắt: đa lớp phát hiện; demo = chữ ký (AC) + CNN (Malimg)  
- Có thể mở rộng DB chữ ký (IOC / hash APT) trong virus_signatures.txt khi có nguồn uy tín  
- Tài liệu trong repo: readme-ml.md, doc-ai-bao-cao-tom-tat.md, doc-ai-hoc-may.md  

**Ghi chú người thuyết trình:**  
Kết thúc: mở Q&A. Gợi ý hướng mở rộng: pipeline import IOC định kỳ, đánh giá FP trên tập benign, logging khớp signature. Tham chiếu học thuật Malimg: Nataraj et al.; code CNN tham chiếu cridin1/malware-classification-CNN nếu cần.

---

## Gợi ý prompt cho AI làm slide

Dán nguyên outline trên và thêm: "Tạo 9 slide, theme chuyên nghiệp, font dễ đọc, slide 6 là sơ đồ luồng (upload → chữ ký → CNN → kết quả)."

# File Virus Mẫu để Test

## ⚠️ LƯU Ý QUAN TRỌNG

**KHÔNG download file virus thật từ internet!** Điều này có thể:
- Vi phạm pháp luật
- Gây hại cho hệ thống
- Rủi ro bảo mật

## ✅ File Test An Toàn

### 1. EICAR Test File (Đã tạo sẵn)
- **File**: `eicar_test.txt`
- **Mô tả**: File test chuẩn của ngành antivirus
- **An toàn**: 100% vô hại, chỉ là file text
- **MD5**: `44d88612fea8a8f36de82e1278abb02f`

### 2. Test File với Pattern (Đã tạo sẵn)
- **File**: `test_pattern.txt`
- **Mô tả**: Chứa pattern từ database để test pattern matching
- **An toàn**: Chỉ chứa text pattern, không phải virus

## 📝 Cách Tạo File Test Thêm

Bạn có thể tạo file test bằng cách:

1. **Tạo file chứa pattern từ database**:
   - Lấy một hex pattern từ `db/virus_signatures.txt`
   - Convert sang bytes và tạo file test

2. **Tạo file với hash cụ thể**:
   - Tính MD5/SHA256 của file
   - Kiểm tra xem hash có trong database không

## 🔗 Nguồn Tham Khảo (Chỉ xem, không download)

Nếu cần file mẫu cho nghiên cứu:

1. **VirusTotal** (https://www.virustotal.com)
   - Upload file để xem kết quả scan
   - Không download file từ đây

2. **EICAR Official** (https://www.eicar.org/)
   - File test chuẩn EICAR
   - Hoàn toàn an toàn

3. **Sandbox Platforms** (Any.run, Joe Sandbox)
   - Phân tích file trong sandbox
   - Không cần download về máy

## 💡 Gợi Ý

Thay vì download virus thật, bạn có thể:
- Tạo file test với các pattern từ database
- Sử dụng EICAR file (đã có sẵn)
- Test với file thông thường để xem scanner hoạt động

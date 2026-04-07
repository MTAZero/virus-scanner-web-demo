# 📁 File Test Mẫu - Tóm Tắt

## ✅ Các File Đã Tạo

### 1. **eicar_test.txt** ⭐
- **Mô tả**: EICAR Standard Antivirus Test File
- **Kích thước**: 68 bytes
- **MD5**: `44d88612fea8a8f36de82e1278abb02f`
- **SHA256**: `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
- **An toàn**: ✅ 100% vô hại
- **Mục đích**: File test chuẩn của ngành antivirus

### 2. **test_with_java_pattern.txt**
- **Mô tả**: File test chứa pattern `java/lang/ClassLoader`
- **Pattern Hex**: `6a6176612f6c616e672f436c6173734c6f61646572`
- **An toàn**: ✅ Chỉ chứa text pattern
- **Mục đích**: Test pattern matching của scanner

## 🚀 Cách Sử Dụng

1. **Upload file lên web scanner**:
   - Mở trình duyệt: `http://localhost:8080`
   - Kéo thả file vào vùng upload hoặc click "Chọn file để quét"
   - Xem kết quả scan

2. **Test với EICAR**:
   ```bash
   # Upload file eicar_test.txt
   # Scanner sẽ phát hiện (nếu có signature trong database)
   ```

3. **Test với pattern**:
   ```bash
   # Upload file test_with_java_pattern.txt
   # Scanner sẽ tìm pattern trong file
   ```

## ⚠️ Lưu Ý

- **KHÔNG** download file virus thật từ internet
- **KHÔNG** sử dụng malware thật để test
- Chỉ sử dụng file test an toàn như EICAR

## 📚 Thông Tin Thêm

Xem file `README.md` và `download_info.md` để biết thêm chi tiết.

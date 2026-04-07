# Dataset Malimg + Benign (cridin1)

## Đã tải sẵn trong máy bạn (thư mục này)

| Thành phần | Mô tả |
|------------|--------|
| `malimg_dataset.zip` | Bản nén gốc Malimg (~1.1 GB), nguồn thường dùng trong tài liệu học thuật (Dropbox mirror công khai). |
| `malimg_extracted/malimg_paper_dataset_imgs/` | 25 thư mục họ mã độc, ảnh PNG (đúng tên lớp như notebook combined_classifier). |
| `cridin1-malware-cnn/benign_data/benign_imgs/` | Ảnh benign từ repo [cridin1/malware-classification-CNN](https://github.com/cridin1/malware-classification-CNN). |
| `malimg_combined/` | Ảnh đã **ghép** 25 lớp + thư mục `Benign/` — dùng thẳng cho `train_cnn.py --malimg-png-root`. |

## Tải lại (máy khác / mất file)

**Malimg (zip):**

```bash
cd datasets
curl -L -o malimg_dataset.zip "https://www.dropbox.com/s/ep8qjakfwh1rzk4/malimg_dataset.zip?dl=1"
unzip -q malimg_dataset.zip -d malimg_extracted
```

**Benign (sparse clone chỉ `benign_data`):**

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/cridin1/malware-classification-CNN.git cridin1-malware-cnn
cd cridin1-malware-cnn && git sparse-checkout set benign_data && cd ..
```

**Ghép 26 lớp:**

```bash
chmod +x prepare_combined.sh
./prepare_combined.sh
```

## Huấn luyện

```bash
cd ../web
python train_cnn.py --malimg-png-root ../datasets/malimg_combined --epochs 10 --batch-size 32
```

**Lưu ý:** Đây là mẫu mã độc / ảnh hóa từ mẫu nghiên cứu — chỉ dùng trong môi trường cô lập, phù hợp chính sách tổ chức của bạn.

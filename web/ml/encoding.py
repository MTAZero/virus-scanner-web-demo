# -*- coding: utf-8 -*-
"""
Chuyển nội dung file nhị phân thành tensor (H, W, 3): mỗi pixel = 3 byte liên tiếp (giống RGB).
"""
from __future__ import annotations

import numpy as np

# Kích thước ảnh vuông (mỗi file dùng tối đa H*W*3 byte đầu)
DEFAULT_IMG_SIZE = 64


def file_to_rgb_tensor(path: str, img_size: int = DEFAULT_IMG_SIZE) -> np.ndarray:
    """Đọc file, cắt/pad về img_size*img_size*3 byte, reshape (img_size, img_size, 3), chuẩn hóa [0,1]."""
    need = img_size * img_size * 3
    with open(path, "rb") as f:
        raw = f.read(need)
    if len(raw) < need:
        raw = raw + b"\x00" * (need - len(raw))
    arr = np.frombuffer(raw, dtype=np.uint8).reshape(img_size, img_size, 3)
    return arr.astype(np.float32) / 255.0


def bytes_to_rgb_tensor(data: bytes, img_size: int = DEFAULT_IMG_SIZE) -> np.ndarray:
    need = img_size * img_size * 3
    raw = data[:need]
    if len(raw) < need:
        raw = raw + b"\x00" * (need - len(raw))
    arr = np.frombuffer(raw, dtype=np.uint8).reshape(img_size, img_size, 3)
    return arr.astype(np.float32) / 255.0

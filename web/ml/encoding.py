# -*- coding: utf-8 -*-
"""
Biểu diễn Malimg / cridin1: byte → ảnh xám (hex2img), resize 256×256, nhân bản 3 kênh
giống ảnh PNG đưa vào ImageDataGenerator (RGB, rescale 1/255).

Tham chiếu: utils/data_conversion.ipynb trong
https://github.com/cridin1/malware-classification-CNN
"""
from __future__ import annotations

from io import BytesIO
from math import log

import numpy as np
from PIL import Image

# Kích thước đầu vào CNN trong notebook combined_classifier (target_size_custom)
MALIMG_DEFAULT_SIZE = 256


def _hex2img_mat(mat: np.ndarray) -> np.ndarray:
    """
    Chuyển mảng 2D (n_hàng, 16) byte → ảnh xám 2D. Logic trùng hex2img() của repo gốc.
    """
    if mat.shape[1] != 16:
        raise ValueError("Malimg cần đúng 16 byte mỗi hàng.")
    a0, sixteen = mat.shape[0], 16
    if a0 == 0:
        return np.zeros((1, 1), dtype=np.uint8)
    b = int((a0 * sixteen) ** 0.5)
    b = 2 ** (int(log(b) / log(2)) + 1)
    a = int(a0 * sixteen / b)
    nrows = a * b // sixteen
    nrows = min(nrows, a0)
    if nrows < 1:
        nrows = 1
    mat = np.asarray(mat[:nrows, :], dtype=np.uint8)
    return mat.reshape(a, b)


def bytes_to_malimg_grayscale(data: bytes) -> np.ndarray:
    """File nhị phân → ảnh xám uint8 (kích thước biến thiên theo Malimg)."""
    if len(data) == 0:
        data = b"\x00" * 16
    arr = np.frombuffer(data, dtype=np.uint8).copy()
    pad = (-len(arr)) % 16
    if pad:
        arr = np.pad(arr, (0, pad), mode="constant", constant_values=0)
    mat = arr.reshape(-1, 16)
    return _hex2img_mat(mat)


def grayscale_to_rgb_tensor(img2d: np.ndarray, target: int = MALIMG_DEFAULT_SIZE) -> np.ndarray:
    """Ảnh xám uint8 → tensor (target, target, 3) float32 [0,1]."""
    im = Image.fromarray(img2d, mode="L")
    im = im.resize((target, target), Image.Resampling.LANCZOS)
    g = np.asarray(im, dtype=np.float32) / 255.0
    return np.stack([g, g, g], axis=-1)


def file_to_malimg_tensor(path: str, target: int = MALIMG_DEFAULT_SIZE) -> np.ndarray:
    """Đọc file bất kỳ (PE, …), mã hóa Malimg → tensor (target, target, 3)."""
    with open(path, "rb") as f:
        raw = f.read()
    g2 = bytes_to_malimg_grayscale(raw)
    return grayscale_to_rgb_tensor(g2, target=target)


def bytes_to_malimg_tensor(data: bytes, target: int = MALIMG_DEFAULT_SIZE) -> np.ndarray:
    g2 = bytes_to_malimg_grayscale(data)
    return grayscale_to_rgb_tensor(g2, target=target)


def file_to_malimg_preview_png_bytes(path: str, max_side: int = 176) -> bytes:
    """Ảnh Malimg xám, resize cạnh dài tối đa max_side → PNG bytes (cho preview UI)."""
    with open(path, "rb") as f:
        raw = f.read()
    g2 = bytes_to_malimg_grayscale(raw)
    im = Image.fromarray(g2, mode="L")
    w, h = im.size
    side = max(w, h, 1)
    if side > max_side:
        scale = max_side / float(side)
        nw = max(1, int(round(w * scale)))
        nh = max(1, int(round(h * scale)))
        im = im.resize((nw, nh), Image.Resampling.LANCZOS)
    buf = BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# --- Tương thích model cũ (64×64, 3 byte/pixel) nếu còn file malware_cnn.keras cũ ---


def file_to_legacy_rgb_tensor(path: str, img_size: int = 64) -> np.ndarray:
    need = img_size * img_size * 3
    with open(path, "rb") as f:
        raw = f.read(need)
    if len(raw) < need:
        raw = raw + b"\x00" * (need - len(raw))
    arr = np.frombuffer(raw, dtype=np.uint8).reshape(img_size, img_size, 3)
    return arr.astype(np.float32) / 255.0

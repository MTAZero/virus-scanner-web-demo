#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huấn luyện CNN phân loại file (byte → ảnh 3 kênh).

Chạy từ thư mục web/:
  cd web && python train_cnn.py --synthetic
  cd web && python train_cnn.py --benign-dir data/benign --malware-dir data/malware

Model lưu tại: web/ml/malware_cnn.keras
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

# Chạy script trực tiếp: thêm web/ vào path
_WEB = Path(__file__).resolve().parent
if str(_WEB) not in sys.path:
    sys.path.insert(0, str(_WEB))

from ml.encoding import DEFAULT_IMG_SIZE, bytes_to_rgb_tensor, file_to_rgb_tensor
from ml.model_def import build_malware_cnn

MODEL_OUT = _WEB / "ml" / "malware_cnn.keras"


def _synthetic_tensors(n_per_class: int, img_size: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Tạo dữ liệu giả lập để demo train nhanh (không thay thế dataset thật)."""
    rng = np.random.default_rng(seed)
    need = img_size * img_size * 3
    xs, ys = [], []
    # benign: byte lặp / có cấu trúc (giả lập văn bản / file đơn giản)
    for _ in range(n_per_class):
        base = rng.integers(20, 120, size=need // 10, dtype=np.uint8)
        raw = (base.tobytes() * (10 * need // len(base) + 1))[:need]
        xs.append(bytes_to_rgb_tensor(raw, img_size))
        ys.append(0)
    # malware: entropy cao hơn (ngẫu nhiên đều)
    for _ in range(n_per_class):
        raw = rng.integers(0, 256, size=need, dtype=np.uint8).tobytes()
        xs.append(bytes_to_rgb_tensor(raw, img_size))
        ys.append(1)
    return np.stack(xs, axis=0), np.array(ys, dtype=np.int32)


def _load_from_folders(benign_dir: Path, malware_dir: Path, img_size: int) -> tuple[np.ndarray, np.ndarray]:
    xs, ys = [], []
    for p in sorted(benign_dir.rglob("*")):
        if p.is_file() and not p.name.startswith("."):
            try:
                xs.append(file_to_rgb_tensor(str(p), img_size))
                ys.append(0)
            except Exception as e:
                print(f"Bỏ qua {p}: {e}")
    for p in sorted(malware_dir.rglob("*")):
        if p.is_file() and not p.name.startswith("."):
            try:
                xs.append(file_to_rgb_tensor(str(p), img_size))
                ys.append(1)
            except Exception as e:
                print(f"Bỏ qua {p}: {e}")
    if len(xs) < 4:
        raise SystemExit("Cần ít nhất vài file trong mỗi thư mục benign/malware.")
    return np.stack(xs, axis=0), np.array(ys, dtype=np.int32)


def main() -> None:
    ap = argparse.ArgumentParser(description="Train malware CNN (byte → RGB image)")
    ap.add_argument("--synthetic", action="store_true", help="Dùng dữ liệu tổng hợp (mặc định nếu không có thư mục)")
    ap.add_argument("--benign-dir", type=Path, default=None)
    ap.add_argument("--malware-dir", type=Path, default=None)
    ap.add_argument("--img-size", type=int, default=DEFAULT_IMG_SIZE)
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--samples-per-class", type=int, default=400, help="Chỉ dùng với --synthetic")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    img_size = args.img_size
    use_folders = args.benign_dir and args.malware_dir

    if use_folders:
        if not args.benign_dir.is_dir() or not args.malware_dir.is_dir():
            raise SystemExit("Thư mục benign hoặc malware không tồn tại.")
        X, y = _load_from_folders(args.benign_dir, args.malware_dir, img_size)
        print(f"Đã load từ thư mục: {X.shape[0]} mẫu")
    else:
        args.synthetic = True
        X, y = _synthetic_tensors(args.samples_per_class, img_size, args.seed)
        print(f"Dữ liệu synthetic: {X.shape[0]} mẫu (demo)")

    rng = np.random.default_rng(args.seed)
    idx = rng.permutation(len(y))
    X, y = X[idx], y[idx]

    split = max(1, int(len(y) * 0.85))
    X_train, X_val = X[:split], X[split:]
    y_train, y_val = y[:split], y[split:]

    model = build_malware_cnn(img_size=img_size)
    model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        epochs=args.epochs,
        batch_size=min(args.batch_size, len(y_train)),
        verbose=1,
    )

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    model.save(MODEL_OUT)
    print(f"Đã lưu model: {MODEL_OUT}")


if __name__ == "__main__":
    main()

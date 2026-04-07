#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huấn luyện CNN theo pipeline
https://github.com/cridin1/malware-classification-CNN
(combined_classifier: ảnh 256×256 RGB, mã hóa Malimg từ byte).

Chạy trong thư mục web/:
  cd web && pip install -r requirements.txt
  cd web && python train_cnn.py
  cd web && python train_cnn.py --malimg-png-root /path/to/dataset
  cd web && python train_cnn.py --malimg-bytes-root /path/to/raw_by_class

Dataset PNG: mỗi thư mục con = một lớp (tên lớp = tên folder), file .png/.jpg…
Dataset byte: mỗi thư mục con = lớp, file nhị phân bất kỳ (PE…) — sẽ được hex2img.

Model: ml/malimg_model.keras | Metadata: ml/malimg_metadata.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

_WEB = Path(__file__).resolve().parent
if str(_WEB) not in sys.path:
    sys.path.insert(0, str(_WEB))

from ml.class_names import MALIMG_COMBINED_CLASSES
from ml.encoding import MALIMG_DEFAULT_SIZE, bytes_to_malimg_tensor, file_to_malimg_tensor
from ml.model_def import build_malware_model_cridin1

MODEL_OUT = _WEB / "ml" / "malimg_model.keras"
META_OUT = _WEB / "ml" / "malimg_metadata.json"
REF = "https://github.com/cridin1/malware-classification-CNN"


def _save_metadata(class_names: list[str]) -> None:
    META_OUT.parent.mkdir(parents=True, exist_ok=True)
    META_OUT.write_text(
        json.dumps(
            {"class_names": class_names, "reference": REF},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Đã lưu metadata: {META_OUT}")


def _synthetic_tensors(
    n_per_class: int,
    img_size: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    rng = np.random.default_rng(seed)
    names = list(MALIMG_COMBINED_CLASSES)
    xs, ys = [], []
    for ci, _ in enumerate(names):
        for _ in range(n_per_class):
            nbytes = int(rng.integers(2000, 65536))
            raw = rng.integers(0, 256, nbytes, dtype=np.uint8).tobytes()
            xs.append(bytes_to_malimg_tensor(raw, target=img_size))
            ys.append(ci)
    y = np.eye(len(names), dtype=np.float32)[ys]
    return np.stack(xs, axis=0), y, names


def _load_bytes_class_dirs(root: Path, img_size: int) -> tuple[np.ndarray, np.ndarray, list[str]]:
    subs = sorted([d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")])
    if len(subs) < 2:
        raise SystemExit("--malimg-bytes-root cần ít nhất 2 thư mục lớp.")
    class_names = [d.name for d in subs]
    xs, ys = [], []
    for yi, sub in enumerate(subs):
        for f in sorted(sub.rglob("*")):
            if not f.is_file() or f.name.startswith("."):
                continue
            try:
                xs.append(file_to_malimg_tensor(str(f), target=img_size))
                ys.append(yi)
            except Exception as e:
                print(f"Bỏ qua {f}: {e}")
    if len(xs) < 4:
        raise SystemExit("Không đủ mẫu sau khi đọc thư mục byte.")
    y = np.eye(len(class_names), dtype=np.float32)[ys]
    return np.stack(xs, axis=0), y, class_names


def main() -> None:
    import tensorflow as tf
    from tensorflow import keras

    ap = argparse.ArgumentParser(
        description="Train Malimg-style CNN (cridin1/malware-classification-CNN)"
    )
    ap.add_argument("--malimg-png-root", type=Path, default=None)
    ap.add_argument("--malimg-bytes-root", type=Path, default=None)
    ap.add_argument("--img-size", type=int, default=MALIMG_DEFAULT_SIZE)
    ap.add_argument("--epochs", type=int, default=10)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--samples-per-class", type=int, default=80, help="Với dữ liệu synthetic")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if args.malimg_png_root and args.malimg_bytes_root:
        raise SystemExit("Chọn một trong hai: --malimg-png-root hoặc --malimg-bytes-root.")

    img_size = args.img_size
    rng = np.random.default_rng(args.seed)

    if args.malimg_png_root:
        if not args.malimg_png_root.is_dir():
            raise SystemExit("malimg-png-root không tồn tại.")
        train_ds = keras.utils.image_dataset_from_directory(
            args.malimg_png_root,
            validation_split=0.2,
            subset="training",
            seed=args.seed,
            image_size=(img_size, img_size),
            batch_size=args.batch_size,
            label_mode="categorical",
        )
        val_ds = keras.utils.image_dataset_from_directory(
            args.malimg_png_root,
            validation_split=0.2,
            subset="validation",
            seed=args.seed,
            image_size=(img_size, img_size),
            batch_size=args.batch_size,
            label_mode="categorical",
        )
        class_names = train_ds.class_names
        num_classes = len(class_names)
        _save_metadata(class_names)

        def _norm(x, y):
            return tf.cast(x, tf.float32) / 255.0, y

        train_ds = train_ds.map(_norm).prefetch(tf.data.AUTOTUNE)
        val_ds = val_ds.map(_norm).prefetch(tf.data.AUTOTUNE)

        model = build_malware_model_cridin1(num_classes=num_classes, img_size=img_size)
        model.fit(train_ds, validation_data=val_ds, epochs=args.epochs, verbose=1)
    elif args.malimg_bytes_root:
        X, y, class_names = _load_bytes_class_dirs(args.malimg_bytes_root, img_size)
        _save_metadata(class_names)
        idx = rng.permutation(len(y))
        X, y = X[idx], y[idx]
        split = max(1, int(len(y) * 0.85))
        X_train, X_val = X[:split], X[split:]
        y_train, y_val = y[:split], y[split:]
        num_classes = y.shape[1]
        model = build_malware_model_cridin1(num_classes=num_classes, img_size=img_size)
        model.fit(
            X_train,
            y_train,
            validation_data=(X_val, y_val),
            epochs=args.epochs,
            batch_size=min(args.batch_size, len(X_train)),
            verbose=1,
        )
    else:
        X, y, class_names = _synthetic_tensors(args.samples_per_class, img_size, args.seed)
        _save_metadata(class_names)
        idx = rng.permutation(len(y))
        X, y = X[idx], y[idx]
        split = max(1, int(len(y) * 0.85))
        X_train, X_val = X[:split], X[split:]
        y_train, y_val = y[:split], y[split:]
        model = build_malware_model_cridin1(num_classes=len(class_names), img_size=img_size)
        model.fit(
            X_train,
            y_train,
            validation_data=(X_val, y_val),
            epochs=args.epochs,
            batch_size=min(args.batch_size, len(X_train)),
            verbose=1,
        )

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    model.save(MODEL_OUT)
    print(f"Đã lưu model: {MODEL_OUT}")


if __name__ == "__main__":
    main()

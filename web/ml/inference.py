# -*- coding: utf-8 -*-
"""Load model CNN (nếu có) và dự đoán xác suất malware."""
from __future__ import annotations

from pathlib import Path

import numpy as np

from .encoding import DEFAULT_IMG_SIZE, file_to_rgb_tensor

# Thư mục chứa app: .../web
_WEB_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = _WEB_DIR / "ml" / "malware_cnn.keras"

_model = None
ML_MODEL_AVAILABLE = False


def _load_model():
    global _model, ML_MODEL_AVAILABLE
    if _model is not None:
        return _model
    if not MODEL_PATH.is_file():
        ML_MODEL_AVAILABLE = False
        return None
    try:
        import tensorflow as tf  # noqa: F401
        from tensorflow import keras

        _model = keras.models.load_model(MODEL_PATH)
        ML_MODEL_AVAILABLE = True
    except Exception as e:
        print(f"[ML] Không load được model: {e}")
        ML_MODEL_AVAILABLE = False
        _model = None
    return _model


def predict_malware_cnn(
    file_path: str,
    img_size: int = DEFAULT_IMG_SIZE,
    threshold: float = 0.5,
) -> dict | None:
    """
    Trả về dict với malware_probability, label, available;
    hoặc None nếu không có model.
    """
    model = _load_model()
    if model is None:
        return {
            "available": False,
            "malware_probability": None,
            "label": None,
            "message": "Chưa có file web/ml/malware_cnn.keras — chạy python train_cnn.py",
        }
    x = file_to_rgb_tensor(file_path, img_size=img_size)
    batch = np.expand_dims(x, axis=0)
    prob = float(model.predict(batch, verbose=0)[0][0])
    label = "malware" if prob >= threshold else "benign"
    return {
        "available": True,
        "malware_probability": round(prob, 4),
        "label": label,
        "threshold": threshold,
    }

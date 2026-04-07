# -*- coding: utf-8 -*-
"""Load model Malimg/cridin1 (softmax) hoặc model nhị phân cũ (sigmoid)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from .class_names import BENIGN_INDEX_MALIMG, MALIMG_COMBINED_CLASSES
from .encoding import MALIMG_DEFAULT_SIZE, file_to_legacy_rgb_tensor, file_to_malimg_tensor

_WEB_DIR = Path(__file__).resolve().parent.parent
MODEL_PRIMARY = _WEB_DIR / "ml" / "malimg_model.keras"
MODEL_LEGACY = _WEB_DIR / "ml" / "malware_cnn.keras"
METADATA_PATH = _WEB_DIR / "ml" / "malimg_metadata.json"

_model = None
_metadata: dict | None = None
ML_MODEL_AVAILABLE = False


def _load_metadata() -> dict:
    global _metadata
    if _metadata is not None:
        return _metadata
    if METADATA_PATH.is_file():
        _metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    else:
        _metadata = {
            "class_names": list(MALIMG_COMBINED_CLASSES),
            "reference": "https://github.com/cridin1/malware-classification-CNN",
        }
    return _metadata


def _load_model():
    global _model, ML_MODEL_AVAILABLE
    if _model is not None:
        return _model
    try:
        from tensorflow import keras
    except Exception as e:
        print(f"[ML] TensorFlow: {e}")
        ML_MODEL_AVAILABLE = False
        return None

    path = MODEL_PRIMARY if MODEL_PRIMARY.is_file() else MODEL_LEGACY
    if not path.is_file():
        ML_MODEL_AVAILABLE = False
        return None
    try:
        _model = keras.models.load_model(path)
        ML_MODEL_AVAILABLE = True
    except Exception as e:
        print(f"[ML] Không load được model: {e}")
        ML_MODEL_AVAILABLE = False
        _model = None
    return _model


def predict_malware_cnn(file_path: str, benign_threshold: float = 0.5) -> dict:
    model = _load_model()
    if model is None:
        return {
            "available": False,
            "message": "Chưa có model — chạy: cd web && python train_cnn.py",
            "reference": "https://github.com/cridin1/malware-classification-CNN",
        }

    out_dim = int(model.output_shape[-1])
    inp = model.input_shape
    h, w = int(inp[1]), int(inp[2])

    if out_dim == 1:
        x = np.expand_dims(file_to_legacy_rgb_tensor(file_path, img_size=h), axis=0)
        prob_mal = float(model.predict(x, verbose=0)[0][0])
        return {
            "available": True,
            "mode": "legacy_binary",
            "malware_probability": round(prob_mal, 4),
            "label": "malware" if prob_mal >= benign_threshold else "benign",
            "threshold": benign_threshold,
        }

    # Malimg / cridin1 softmax
    target = h if h == w else MALIMG_DEFAULT_SIZE
    x = np.expand_dims(file_to_malimg_tensor(file_path, target=target), axis=0)
    probs = model.predict(x, verbose=0)[0]
    meta = _load_metadata()
    names = meta.get("class_names") or list(MALIMG_COMBINED_CLASSES)
    if len(names) != len(probs):
        names = [f"class_{i}" for i in range(len(probs))]

    idx = int(np.argmax(probs))
    pred_name = names[idx]
    if "Benign" in names:
        p_benign = float(probs[names.index("Benign")])
    elif len(names) == len(MALIMG_COMBINED_CLASSES):
        p_benign = float(probs[BENIGN_INDEX_MALIMG])
    else:
        p_benign = float(probs[idx] if pred_name == "Benign" else 0.0)

    order = np.argsort(-probs)
    top5 = [
        {"class": names[int(i)], "probability": round(float(probs[int(i)]), 4)}
        for i in order[:5]
        if int(i) < len(names)
    ]

    is_benign_pred = pred_name == "Benign"

    return {
        "available": True,
        "mode": "malimg_cridin1",
        "reference": "https://github.com/cridin1/malware-classification-CNN",
        "predicted_class": pred_name,
        "predicted_index": idx,
        "probabilities_top5": top5,
        "benign_probability": round(p_benign, 4),
        "is_benign_prediction": is_benign_pred,
        "malware_probability": round(1.0 - p_benign, 4),
        "label": "benign" if is_benign_pred else "malware_family",
    }


def model_paths_for_health() -> dict:
    return {
        "malimg_model": str(MODEL_PRIMARY),
        "legacy_model": str(MODEL_LEGACY),
        "metadata": str(METADATA_PATH),
    }

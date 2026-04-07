# -*- coding: utf-8 -*-
"""
Kiến trúc Sequential trong combined_classifier_val.ipynb
https://github.com/cridin1/malware-classification-CNN

target_size (256, 256), 3 kênh; softmax đa lớp.
"""
from __future__ import annotations

from tensorflow import keras
from tensorflow.keras import layers

from .encoding import MALIMG_DEFAULT_SIZE


def build_malware_model_cridin1(
    num_classes: int,
    img_size: int = MALIMG_DEFAULT_SIZE,
) -> keras.Model:
    h = w = img_size
    m = keras.Sequential(
        [
            layers.Input(shape=(h, w, 3)),
            layers.Conv2D(64, kernel_size=(3, 3), activation="relu"),
            layers.MaxPooling2D(pool_size=(2, 2)),
            layers.Conv2D(32, kernel_size=(3, 3), activation="relu"),
            layers.MaxPooling2D(pool_size=(2, 2)),
            layers.Conv2D(32, kernel_size=(3, 3), activation="relu"),
            layers.MaxPooling2D(pool_size=(2, 2)),
            layers.Conv2D(16, (3, 3), activation="relu"),
            layers.MaxPooling2D(pool_size=(2, 2)),
            layers.Dropout(0.25),
            layers.Flatten(),
            layers.Dense(128, activation="relu"),
            layers.Dropout(0.25),
            layers.Dense(50, activation="relu"),
            layers.Dropout(0.5),
            layers.Dense(num_classes, activation="softmax"),
        ],
        name="malware_model_cridin1_combined",
    )
    m.compile(
        optimizer="adam",
        loss="categorical_crossentropy",
        metrics=["accuracy"],
    )
    return m

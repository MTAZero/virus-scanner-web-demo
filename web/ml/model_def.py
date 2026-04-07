# -*- coding: utf-8 -*-
"""CNN nhỏ: 2 khối Conv + GlobalAveragePooling + Dense."""
from __future__ import annotations

from tensorflow import keras
from tensorflow.keras import layers

from .encoding import DEFAULT_IMG_SIZE


def build_malware_cnn(img_size: int = DEFAULT_IMG_SIZE) -> keras.Model:
    inputs = keras.Input(shape=(img_size, img_size, 3))
    x = layers.Conv2D(32, 3, activation="relu", padding="same")(inputs)
    x = layers.MaxPooling2D(2)(x)
    x = layers.Conv2D(64, 3, activation="relu", padding="same")(x)
    x = layers.MaxPooling2D(2)(x)
    x = layers.GlobalAveragePooling2D()(x)
    x = layers.Dense(32, activation="relu")(x)
    x = layers.Dropout(0.3)(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    model = keras.Model(inputs, outputs, name="malware_byte_cnn")
    model.compile(
        optimizer=keras.optimizers.Adam(1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model

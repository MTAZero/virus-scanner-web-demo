# -*- coding: utf-8 -*-
"""
Thứ tự lớp khớp combined_classifier trong
https://github.com/cridin1/malware-classification-CNN
(combined_classifier_val.ipynb — class_index).
"""
from __future__ import annotations

# 26 lớp: index 6 = Benign
MALIMG_COMBINED_CLASSES: tuple[str, ...] = (
    "Adialer.C",
    "Agent.FYI",
    "Allaple.A",
    "Allaple.L",
    "Alueron.gen!J",
    "Autorun.K",
    "Benign",
    "C2LOP.P",
    "C2LOP.gen!g",
    "Dialplatform.B",
    "Dontovo.A",
    "Fakerean",
    "Instantaccess",
    "Lolyda.AA1",
    "Lolyda.AA2",
    "Lolyda.AA3",
    "Lolyda.AT",
    "Malex.gen!J",
    "Obfuscator.AD",
    "Rbot!gen",
    "Skintrim.N",
    "Swizzor.gen!E",
    "Swizzor.gen!I",
    "VB.AT",
    "Wintrim.BX",
    "Yuner.A",
)

BENIGN_INDEX_MALIMG = MALIMG_COMBINED_CLASSES.index("Benign")

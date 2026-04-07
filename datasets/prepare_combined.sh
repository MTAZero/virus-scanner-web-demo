#!/usr/bin/env bash
# Ghép Malimg (25 lớp) + Benign → malimg_combined/ cho train_cnn.py
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_MAL="$DIR/malimg_extracted/malimg_paper_dataset_imgs"
SRC_BEN="$DIR/cridin1-malware-cnn/benign_data/benign_imgs"
OUT="$DIR/malimg_combined"

if [[ ! -d "$SRC_MAL" ]]; then
  echo "Thiếu $SRC_MAL — giải nén malimg_dataset.zip vào malimg_extracted/"
  exit 1
fi
if [[ ! -d "$SRC_BEN" ]]; then
  echo "Thiếu $SRC_BEN — clone benign_data (xem datasets/README.md)"
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

for d in "$SRC_MAL"/*; do
  [[ -d "$d" ]] || continue
  name="$(basename "$d")"
  cp -R "$d" "$OUT/$name"
done

mkdir -p "$OUT/Benign"
cp "$SRC_BEN"/*.png "$OUT/Benign/" 2>/dev/null || true

echo "OK: $OUT"
echo "  Lớp: $(ls -1 "$OUT" | wc -l | tr -d ' ') thư mục"

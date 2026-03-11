#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python -m pip install -r requirements-dev.txt

pyinstaller \
  --noconfirm \
  --clean \
  --name visualRoutePython \
  --windowed \
  --collect-all PySide6 \
  --hidden-import PySide6.QtWebEngineWidgets \
  app.py

echo "Build completado. Binarios en: $ROOT_DIR/dist/visualRoutePython"

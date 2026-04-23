#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LIB_DIR="$PROJECT_ROOT/TA-epss/bin/lib"

echo "==> Cleaning existing vendored dependencies..."
rm -rf "$LIB_DIR"
mkdir -p "$LIB_DIR"

echo "==> Installing pure-Python dependencies into $LIB_DIR..."
pip install \
    --target "$LIB_DIR" \
    --no-compile \
    --no-deps \
    requests urllib3 certifi charset-normalizer idna splunk-sdk

echo "==> Cleaning up unnecessary files..."
find "$LIB_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$LIB_DIR" -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find "$LIB_DIR" -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
find "$LIB_DIR" -name "*.so" -delete 2>/dev/null || true
find "$LIB_DIR" -name "*.dylib" -delete 2>/dev/null || true
find "$LIB_DIR" -name "*.pyd" -delete 2>/dev/null || true
find "$LIB_DIR" -name "*.pyc" -delete 2>/dev/null || true

echo "==> Vendored dependencies:"
ls -1 "$LIB_DIR"
echo "==> Done."

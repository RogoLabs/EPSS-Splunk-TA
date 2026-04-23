#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

VERSION=$(grep 'version' TA-epss/default/app.conf | head -1 | awk -F'= ' '{print $2}' | tr -d '[:space:]')
OUTPUT="TA-epss-${VERSION}.tar.gz"

echo "==> Building $OUTPUT..."

COPYFILE_DISABLE=1 tar czf "$OUTPUT" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    --exclude='._*' \
    --exclude='local' \
    --exclude='local.meta' \
    TA-epss/

echo "==> Package contents:"
tar tzf "$OUTPUT" | head -30

echo ""
echo "==> Built: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"

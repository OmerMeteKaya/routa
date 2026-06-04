#!/usr/bin/env bash
# Triage AFL++ findings — print unique crash inputs

TARGET=${1:-request}
FINDINGS="fuzz/findings/${TARGET}"
BUILD_DIR=${BUILD_DIR:-build_afl}
BINARY="$BUILD_DIR/fuzz/afl_fuzz_${TARGET}"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    exit 1
fi

echo "=== CRASHES ==="
for f in "$FINDINGS"/*/crashes/id:*; do
    [ -f "$f" ] || continue
    echo "--- $f ---"
    "$BINARY" < "$f" 2>&1 | tail -5
    echo ""
done

echo "=== HANGS ==="
for f in "$FINDINGS"/*/hangs/id:*; do
    [ -f "$f" ] || continue
    echo "--- $f ($(wc -c < "$f") bytes) ---"
done

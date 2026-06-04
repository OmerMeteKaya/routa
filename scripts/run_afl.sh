#!/usr/bin/env bash
# Usage: ./scripts/run_afl.sh [target] [jobs]
# Example: ./scripts/run_afl.sh request 4

set -e

TARGET=${1:-request}
JOBS=${2:-4}
BUILD_DIR=${BUILD_DIR:-build_afl}
CORPUS="fuzz/corpus/${TARGET}"
FINDINGS="fuzz/findings/${TARGET}"

mkdir -p "$FINDINGS"

# Build if needed
if [ ! -f "$BUILD_DIR/fuzz/afl_fuzz_${TARGET}" ]; then
    cmake -B "$BUILD_DIR" -DROUTA_AFL=ON -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_C_COMPILER=afl-clang-fast \
          -DCMAKE_CXX_COMPILER=afl-clang-fast++ 2>&1 | grep -v "Performing" || true
    cmake --build "$BUILD_DIR" --target "afl_fuzz_${TARGET}" -j$(nproc)
fi

BINARY="$BUILD_DIR/fuzz/afl_fuzz_${TARGET}"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY"
    exit 1
fi

# Core pattern (Linux)
echo core | sudo tee /proc/sys/kernel/core_pattern 2>/dev/null || true

# Single job
if [ "$JOBS" -eq 1 ]; then
    afl-fuzz -i "$CORPUS" -o "$FINDINGS" \
             -m none -t 1000 \
             -- "$BINARY"
    exit 0
fi

# Multi-core: 1 master + N-1 secondary
afl-fuzz -i "$CORPUS" -o "$FINDINGS" \
         -m none -t 1000 -M master \
         -- "$BINARY" &

for i in $(seq 1 $((JOBS - 1))); do
    afl-fuzz -i "$CORPUS" -o "$FINDINGS" \
             -m none -t 1000 -S "worker_${i}" \
             -- "$BINARY" &
done

wait

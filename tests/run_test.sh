#!/usr/bin/env bash
set -e

TEST=$1

if [ -f "build/${TEST}" ]; then
    BINARY="build/${TEST}"
elif [ -f "./${TEST}" ]; then
    BINARY="./${TEST}"
else
    echo "ERROR: ${TEST} not found"
    exit 1
fi

# Kill leftover processes on test ports
fuser -k 18080/tcp 18081/tcp 18443/tcp 2>/dev/null || true
sleep 0.5

timeout 120 "$BINARY"
EXIT_CODE=$?

fuser -k 18080/tcp 18081/tcp 18443/tcp 2>/dev/null || true

if [ $EXIT_CODE -eq 124 ]; then
    echo "ERROR: ${TEST} timed out after 120s"
    exit 1
fi

exit $EXIT_CODE
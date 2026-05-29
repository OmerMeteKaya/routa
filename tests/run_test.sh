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

# Kill leftover processes on test ports (fuser is Linux-only)
kill_port() {
    local port=$1
    # Linux
    if command -v lsof >/dev/null 2>&1; then
        lsof -ti "tcp:${port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    # BSD (FreeBSD/OpenBSD/NetBSD)
    elif command -v sockstat >/dev/null 2>&1; then
        sockstat -4 -l -p "${port}" 2>/dev/null \
            | awk 'NR>1 {print $3}' \
            | xargs kill -9 2>/dev/null || true
    fi
}
kill_port 18080
kill_port 18081
kill_port 18443
sleep 0.5

# timeout is GNU coreutils (Linux); gtimeout via brew on macOS
if command -v timeout >/dev/null 2>&1; then
    timeout 120 "$BINARY"
    EXIT_CODE=$?
elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout 120 "$BINARY"
    EXIT_CODE=$?
else
    "$BINARY" &
    BG_PID=$!
    sleep 120 &
    SLEEP_PID=$!
    wait -n $BG_PID $SLEEP_PID 2>/dev/null
    EXIT_CODE=$?
    kill $BG_PID $SLEEP_PID 2>/dev/null || true
fi

kill_port 18080
kill_port 18081
kill_port 18443

if [ $EXIT_CODE -eq 124 ]; then
    echo "ERROR: ${TEST} timed out after 120s"
    exit 1
fi

exit $EXIT_CODE
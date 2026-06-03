#!/bin/bash
# examples/bench.sh

SERVER="https://localhost:18443"
SESS="/tmp/routa_bench_sess.bin"
THREADS=12
CONNS=200
STREAMS=50

echo "=== ROUTA Benchmark Suite ==="
echo "Warming up session tickets..."

h2load -n500 -c1 -m1 -t1 \
  --tls-session-file="$SESS"  \
  "$SERVER/hello" > /dev/null 2>&1

echo ""
echo "--- Hello (12B) ---"
h2load -n100000 -c$CONNS -m$STREAMS -t$THREADS  \
  --tls-session-file="$SESS" "$SERVER/hello"

echo ""
echo "--- Small (4KB) ---"
h2load -n100000 -c$CONNS -m$STREAMS -t$THREADS  \
  --tls-session-file="$SESS" "$SERVER/small"

echo ""
echo "--- Medium (64KB) ---"
h2load -n100000 -c$CONNS -m$STREAMS -t$THREADS  \
  --tls-session-file="$SESS" "$SERVER/medium"

echo ""
echo "--- Larger (1MB) ---"
h2load -n50000 -c$CONNS/2 -m$STREAMS -t$THREADS  \
  --tls-session-file="$SESS" "$SERVER/larger"

echo ""
echo "--- Large (128KB) ---"
h2load -n100000 -c$CONNS -m$STREAMS -t$THREADS  \
  --tls-session-file="$SESS" "$SERVER/large"

echo ""
echo "=== Done ==="
rm -f "$SESS"
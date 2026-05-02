#!/bin/bash
# Benchmark static file serving before/after sendfile
# Requires wrk: https://github.com/wg/wrk
# Usage: ./bench_static.sh [host] [port]
HOST=${1:-localhost}
PORT=${2:-8080}
echo "=== Static file benchmark ==="
echo "--- Small file (index.html) ---"
wrk -t4 -c100 -d10s http://$HOST:$PORT/index.html
echo "--- Keep-alive throughput ---"
wrk -t4 -c100 -d10s -H "Connection: keep-alive" http://$HOST:$PORT/
echo "=== Done ==="

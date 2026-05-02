#!/bin/bash
# Requires wrk2: https://github.com/giltene/wrk2
echo "=== Latency distribution (requires wrk2) ==="
wrk2 -t4 -c100 -d30s -R5000 --latency http://${1:-localhost}:${2:-8080}/
echo "=== Done ==="

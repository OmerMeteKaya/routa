#!/bin/bash
echo "=== TLS handshake benchmark ==="
openssl s_time -connect ${1:-localhost}:${2:-8080} -new -time 10
echo "=== Done ==="

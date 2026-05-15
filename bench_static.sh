#!/usr/bin/env bash
# bench_static.sh — mmap + file cache benchmark
# Kullanım: ./bench_static.sh [host] [port] [url_path]
# Örnek:    ./bench_static.sh 127.0.0.1 8080 /index.html

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8080}"
PATH_SMALL="${3:-/index.html}"   # < 64 KB — mmap path
PATH_LARGE="${4:-/large.bin}"    # ≥ 64 KB — sendfile path

BASE_URL="http://${HOST}:${PORT}"
DURATION=30
THREADS=12
CONNS=1200
RATE=200000

# ── Renk ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

# ── Bağımlılık kontrol ───────────────────────────────────────────────────────
for tool in wrk2 curl bc; do
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${RED}HATA: '$tool' bulunamadı.${NC}"
        [[ "$tool" == "wrk2" ]] && echo "  → https://github.com/giltene/wrk2"
        exit 1
    fi
done

# ── Test dosyaları oluştur (sunucuda yoksa uyar) ─────────────────────────────
echo -e "${CYAN}${BOLD}── Sunucu erişim kontrolü ──────────────────────────────────${NC}"
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" "${BASE_URL}${PATH_SMALL}" || true)
if [[ "$HTTP_CODE" != "200" ]]; then
    echo -e "${RED}UYARI: ${BASE_URL}${PATH_SMALL} → HTTP $HTTP_CODE${NC}"
    echo "  Sunucunun çalıştığından ve test dosyasının mevcut olduğundan emin ol."
    echo "  Küçük dosya oluşturmak için:"
    echo "    dd if=/dev/urandom of=<doc_root>/index.html bs=1K count=10"
    echo "  Büyük dosya oluşturmak için:"
    echo "    dd if=/dev/urandom of=<doc_root>/large.bin  bs=1K count=512"
    exit 1
fi
echo -e "${GREEN}OK — sunucu yanıt veriyor${NC}"

run_bench() {
    local label="$1"
    local url="$2"
    local out
    out=$(wrk2 -t"$THREADS" -c"$CONNS" -d"${DURATION}s" -R"$RATE" \
          --latency "$url" 2>&1)

    local rps p50 p99 p999 errors
    rps=$(echo "$out"   | grep "Requests/sec" | awk '{print $2}')
    p50=$(echo "$out"   | grep "50.000%" | awk '{print $2}')
    p99=$(echo "$out"   | grep "99.000%" | awk '{print $2}')
    p999=$(echo "$out"  | grep "99.900%" | awk '{print $2}')
    errors=$(echo "$out" | grep -E "Non-2xx|Socket errors" | awk '{sum += $NF} END {print sum+0}')

    echo -e "${BOLD}${label}${NC}"
    echo "  URL      : $url"
    printf "  Req/s    : ${GREEN}%s${NC}\n" "$rps"
    printf "  p50      : %s\n" "$p50"
    printf "  p99      : %s\n" "$p99"
    printf "  p99.9    : %s\n" "$p999"
    printf "  Hatalar  : %s\n" "$errors"
    echo ""
}

# ── Warmup ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}── Warmup (5s) ─────────────────────────────────────────────${NC}"
wrk2 -t4 -c100 -d5s -R10000 "${BASE_URL}${PATH_SMALL}" &>/dev/null || true
echo "Warmup tamamlandı."
echo ""

# ── Benchmark ────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}── Benchmark Başlıyor ──────────────────────────────────────${NC}"
echo "  threads=$THREADS  conns=$CONNS  duration=${DURATION}s  rate=$RATE"
echo ""

run_bench "1) Küçük dosya — mmap path (< 64 KB)" \
          "${BASE_URL}${PATH_SMALL}"

run_bench "2) Büyük dosya — sendfile path (>= 64 KB)" \
          "${BASE_URL}${PATH_LARGE}"

# ── Cache ısınma testi ───────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}── Cache hit vs cold start (küçük dosya) ───────────────────${NC}"
echo "Cold (ilk 5 saniye, cache dolmadan):"
wrk2 -t4 -c200 -d5s -R50000 --latency "${BASE_URL}${PATH_SMALL}" 2>&1 \
    | grep -E "Requests/sec|99.000%"

echo ""
echo "Hot (cache dolu, 30 saniye):"
wrk2 -t"$THREADS" -c"$CONNS" -d"${DURATION}s" -R"$RATE" --latency \
    "${BASE_URL}${PATH_SMALL}" 2>&1 \
    | grep -E "Requests/sec|50.000%|99.000%"

echo ""
echo -e "${GREEN}${BOLD}Benchmark tamamlandı.${NC}"

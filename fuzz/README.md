# Fuzzing

This directory contains fuzz targets for libFuzzer and AFL++ testing.

## Targets

- `fuzz_request` — HTTP/1.1 request parser
- `fuzz_hpack` — HTTP/2 header compression (HPACK) decoder
- `fuzz_ws` — WebSocket frame decoder
- `fuzz_h2_frame` — HTTP/2 frame parser

## libFuzzer

Build:

```bash
cmake -B build -DFUZZ=ON
cmake --build build
```

Run:

```bash
cd build/fuzz
./fuzz_request ../../fuzz/corpus/request -max_len=4096 -timeout=10
./fuzz_hpack ../../fuzz/corpus/hpack -max_len=4096 -timeout=10
./fuzz_ws ../../fuzz/corpus/ws -max_len=65536 -timeout=10
./fuzz_h2_frame ../../fuzz/corpus/h2_frame -max_len=65536 -timeout=10
```

## AFL++ (Persistent Mode)

Build:

```bash
cmake -B build_afl -DROUTA_AFL=ON \
  -DCMAKE_C_COMPILER=afl-clang-fast \
  -DCMAKE_CXX_COMPILER=afl-clang-fast++
cmake --build build_afl
```

Run single target (4 cores):

```bash
./scripts/run_afl.sh request 4
```

Run all targets:

```bash
for target in request hpack ws h2_frame; do
  ./scripts/run_afl.sh $target 4 &
done
wait
```

Triage crashes:

```bash
./scripts/afl_triage.sh request
```

Sync corpus back to libFuzzer:

```bash
./scripts/corpus_sync.sh
```

## Corpus

Each target has a seed corpus in `fuzz/corpus/<target>/`. AFL++ findings are stored in `fuzz/findings/<target>/`.

The corpus is shared between libFuzzer and AFL++ — both can use the same test inputs.

## CI/CD

- **libFuzzer** runs for 10 minutes per target in the nightly workflow (`fuzz-long` job)
- **AFL++** runs for 5 minutes per target in the nightly workflow (`afl-fuzz` job)
- Crashes and hangs are uploaded as artifacts for analysis

## Prerequisites

AFL++:

```bash
# Arch
sudo pacman -S afl++

# Ubuntu
sudo apt-get install afl++

# macOS
brew install afl-plus-plus
```

Or build from source:

```bash
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

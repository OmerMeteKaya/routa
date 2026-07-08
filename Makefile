# ═══════════════════════════════════════════════════════════════════════════
# routa — top-level build convenience wrapper around CMake.
#
# This Makefile does not replace CMake -- it's a thin, memorable set of
# shortcuts over `cmake -B <dir> ... && cmake --build <dir> && ctest`, so
# day-to-day commands don't require remembering which build directory maps
# to which sanitizer/build-type combination. Every target is safe to run
# repeatedly; build directories are created on demand and never shared
# between configurations (each sanitizer/build-type gets its own directory,
# so switching between them never requires a clean rebuild of another).
#
# Common targets:
#   make release        Release build (build_release/)
#   make debug          Debug build, no sanitizer (build_debug/)
#   make asan           Debug + ASan/UBSan (build_asan/)
#   make ubsan          Debug + UBSan only (build_ubsan/)
#   make tsan           Debug + ThreadSanitizer (build_tsan/)
#   make msan           Debug + MemorySanitizer, requires clang (build_msan/)
#   make numa           Release build with -DROUTA_NUMA=ON (build_numa/)
#
#   make test           Run ctest against the release build (builds first)
#   make test-asan      Run ctest under build_asan (builds first)
#   make test-tsan      Run ctest under build_tsan (builds first)
#   make test-ubsan     Run ctest under build_ubsan (builds first)
#   make test-msan      Run ctest under build_msan (builds first)
#   make test-all       Run ctest under every sanitizer build in sequence,
#                       stopping at the first failure (asan -> ubsan -> tsan
#                       -> msan) -- the closest thing to a full pre-release
#                       sanity sweep this project currently has.
#
#   make clean          Remove every build_* directory
#   make clean-<name>   Remove a single build_<name> directory (e.g. `make
#                       clean-asan`)
#
# All build directories are Debug builds except `release` and `numa`, since
# sanitizers need debug info and unoptimized code to produce useful,
# accurate diagnostics (see cmake/Sanitizers.cmake's own comment on this).
# ═══════════════════════════════════════════════════════════════════════════

# Parallelism for the underlying `cmake --build` invocations. Override with
# `make -j8 release` or `MAKE_JOBS=8 make release` if nproc guesses wrong.
MAKE_JOBS ?= $(shell nproc 2>/dev/null || echo 4)

.PHONY: all release debug asan ubsan tsan msan numa \
        test test-release test-asan test-ubsan test-tsan test-msan test-all \
        clean clean-release clean-debug clean-asan clean-ubsan clean-tsan clean-msan clean-numa \
        help

all: release

help:
	@echo "See the comment block at the top of this Makefile for the full target list."
	@echo "Quick start: make release && make test"

# ── Plain builds ─────────────────────────────────────────────────────────
release:
	cmake -B build_release -DCMAKE_BUILD_TYPE=Release
	cmake --build build_release -j$(MAKE_JOBS)

debug:
	cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
	cmake --build build_debug -j$(MAKE_JOBS)

numa:
	cmake -B build_numa -DCMAKE_BUILD_TYPE=Release -DROUTA_NUMA=ON
	cmake --build build_numa -j$(MAKE_JOBS)

# ── Sanitizer builds (always Debug -- see comment above) ─────────────────
asan:
	cmake -B build_asan -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=asan
	cmake --build build_asan -j$(MAKE_JOBS)

ubsan:
	cmake -B build_ubsan -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=ubsan
	cmake --build build_ubsan -j$(MAKE_JOBS)

tsan:
	cmake -B build_tsan -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=tsan
	cmake --build build_tsan -j$(MAKE_JOBS)

msan:
	cmake -B build_msan -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=msan -DCMAKE_C_COMPILER=clang
	cmake --build build_msan -j$(MAKE_JOBS)

# ── Test targets ──────────────────────────────────────────────────────────
# ctest must run with the project root as its working directory (several
# tests, e.g. test_config/test_proxy_lb, load fixture files by a path
# relative to the repo root, not the build directory) -- `cd` into the
# build dir only for ctest's own bookkeeping, then run it with --test-dir
# pointing back to run from the repo root's perspective is awkward with
# plain ctest, so instead we just `cd` into the build dir (ctest's default
# expectation) and rely on the CMakeLists.txt test registrations that
# already set WORKING_DIRECTORY where needed (test_config, test_proxy_lb).
test: release
	cd build_release && ctest --output-on-failure

test-release: release
	cd build_release && ctest --output-on-failure

test-asan: asan
	cd build_asan && ctest --output-on-failure

test-ubsan: ubsan
	cd build_ubsan && ctest --output-on-failure

test-tsan: tsan
	cd build_tsan && ctest --output-on-failure

test-msan: msan
	cd build_msan && ctest --output-on-failure

# Runs the full sanitizer sweep in sequence, stopping at the first failure
# (so a real ASan crash doesn't get buried under three more build logs).
test-all: test-asan test-ubsan test-tsan test-msan
	@echo "All sanitizer test suites passed."

# ── Cleanup ────────────────────────────────────────────────────────────────
clean:
	rm -rf build_release build_debug build_asan build_ubsan build_tsan build_msan build_numa

clean-release:
	rm -rf build_release

clean-debug:
	rm -rf build_debug

clean-asan:
	rm -rf build_asan

clean-ubsan:
	rm -rf build_ubsan

clean-tsan:
	rm -rf build_tsan

clean-msan:
	rm -rf build_msan

clean-numa:
	rm -rf build_numa

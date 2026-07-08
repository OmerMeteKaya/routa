# ═══════════════════════════════════════════════════════════════════════════
# Sanitizers — one mutually-exclusive selector, not independent toggles.
#
# ASAN, TSAN, and MSAN instrument memory/threading in incompatible ways and
# cannot be combined in a single binary (attempting to link -fsanitize=address
# together with -fsanitize=thread, for instance, is a hard compiler/linker
# error, not just an unsupported combination). UBSAN is cheap and compatible
# with ASAN, so it's bundled into the "asan" and default builds; it's also
# available alone. Pick exactly one via -DSANITIZER=<name>:
#
#   none        (default) no sanitizer, e.g. for the plain release build.
#   asan        AddressSanitizer + UndefinedBehaviorSanitizer. Catches heap/
#               stack buffer overflows, use-after-free, double-free, and UB
#               (signed overflow, misaligned access, etc). The everyday
#               "run this on every test suite pass" sanitizer.
#   ubsan       UndefinedBehaviorSanitizer alone (no ASAN overhead) -- useful
#               when you specifically want UB-only diagnostics without
#               ASAN's larger memory/runtime overhead.
#   tsan        ThreadSanitizer. Data races, lock-order inversions. Routa is
#               heavily multi-threaded (worker threads, health-check thread,
#               shared upstream_pool_t/lb_t state guarded by spinlocks/
#               mutexes/atomics) -- this is the sanitizer most likely to
#               catch a genuinely subtle bug in this codebase, and should
#               be run under real concurrent load (not just the unit test
#               suite, which is mostly single-connection) to be meaningful.
#   msan        MemorySanitizer. Reads of uninitialized memory. Clang-only
#               (GCC does not implement MSAN) -- CMake errors out clearly
#               if requested with a non-Clang compiler rather than silently
#               producing an uninstrumented binary.
#
# Usage: cmake -B build_asan -DSANITIZER=asan -DCMAKE_BUILD_TYPE=Debug ..
# (Debug is strongly recommended with any sanitizer: -O2 can optimize away
# or reorder the exact code patterns these tools are trying to catch, and
# stack traces are far more useful with debug info and without inlining.)
# ═══════════════════════════════════════════════════════════════════════════

set(SANITIZER "none" CACHE STRING "Sanitizer to build with: none|asan|ubsan|tsan|msan")
set_property(CACHE SANITIZER PROPERTY STRINGS none asan ubsan tsan msan)

if(NOT SANITIZER STREQUAL "none")
    if(NOT (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"))
        message(FATAL_ERROR "Sanitizer '${SANITIZER}' requested but compiler '${CMAKE_C_COMPILER_ID}' is neither GCC nor Clang")
    endif()

    if(SANITIZER STREQUAL "msan" AND NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "MemorySanitizer (msan) requires Clang -- GCC does not implement MSAN. Rebuild with -DCMAKE_C_COMPILER=clang")
    endif()

    if(SANITIZER STREQUAL "asan")
        set(_SAN_FLAGS "-fsanitize=address,undefined")
    elseif(SANITIZER STREQUAL "ubsan")
        set(_SAN_FLAGS "-fsanitize=undefined")
    elseif(SANITIZER STREQUAL "tsan")
        set(_SAN_FLAGS "-fsanitize=thread")
    elseif(SANITIZER STREQUAL "msan")
        set(_SAN_FLAGS "-fsanitize=memory -fsanitize-memory-track-origins")
    else()
        message(FATAL_ERROR "Unknown SANITIZER value '${SANITIZER}' (expected none|asan|ubsan|tsan|msan)")
    endif()

    add_compile_options(${_SAN_FLAGS} -fno-omit-frame-pointer -g)
    add_link_options(${_SAN_FLAGS})
    message(STATUS "Sanitizer: ${SANITIZER} enabled (${_SAN_FLAGS})")
else()
    message(STATUS "Sanitizer: none")
endif()

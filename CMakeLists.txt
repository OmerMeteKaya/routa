cmake_minimum_required(VERSION 3.20)
project(routa VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(cmake/CompileFlags.cmake)

# ── Options ──────────────────────────────────────────────────────────────────
option(ROUTA_NUMA "Enable NUMA-aware worker placement (requires libnuma, Linux only)" OFF)
option(ACCESS_LOG "Enable JSON access logging" OFF)
if(ACCESS_LOG)
  target_compile_definitions(routa_core PRIVATE ROUTA_ACCESS_LOG)
endif()

# ── Dependency search paths (macOS Homebrew) ─────────────────────────────────
if(APPLE)
  list(APPEND CMAKE_PREFIX_PATH
            "/opt/homebrew/opt/openssl@3"
            "/usr/local/opt/openssl@3")
endif()

# ── Required dependencies ────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB    REQUIRED)

# ── Sources ──────────────────────────────────────────────────────────────────
file(GLOB_RECURSE ROUTA_SOURCES
        src/core/*.c
        src/http/*.c
        src/net/socket.c
        src/net/poller.c
        src/net/io.c
        src/net/tls.c
        src/net/h2_client.c
        src/util/*.c
        src/lb/*.c
)

# ── Core library ─────────────────────────────────────────────────────────────
add_library(routa_core STATIC ${ROUTA_SOURCES}
        src/http/ws.c
        src/http/ws_registry.c
        include/http/ws.h
        include/http/ws_registry.h
        src/http/h2.c
        src/http/h2_hpack.c
        include/http/h2.h
        include/http/cookie.h
        src/http/cookie.c
        include/http/mw_auth.h
        src/http/mw_auth.c
        src/http/mw_acl.c
        src/util/metrics.c
        src/http/mw_metrics.c
        include/util/metrics.h
        include/http/mw_metrics.h
        include/core/proxy.h
        src/core/proxy.c)

target_include_directories(routa_core PUBLIC include)

target_link_libraries(routa_core PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        ZLIB::ZLIB
)
target_link_libraries(routa_core PRIVATE z)

# ── NUMA (Linux only, opt-in) ─────────────────────────────────────────────────
if(ROUTA_NUMA)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "NUMA awareness is Linux-only")
    endif()
    find_library(LIBNUMA_LIB numa REQUIRED)
    find_path(LIBNUMA_INCLUDE_DIR numa.h REQUIRED)
    target_sources(routa_core PRIVATE src/core/numa.c)
    target_link_libraries(routa_core PRIVATE ${LIBNUMA_LIB})
    target_compile_definitions(routa_core PUBLIC ROUTA_NUMA)
    message(STATUS "NUMA awareness: enabled")
else()
    message(STATUS "NUMA awareness: disabled")
endif()

# ── Main binary ───────────────────────────────────────────────────────────────
# The actual "run this to host a site" production binary: loads a config
# file (default "routa.conf", or argv[1]) and serves it -- see src/main.c.
# This is what `./routa /etc/routa/routa.conf` means in practice.
add_executable(routa src/main.c)
target_link_libraries(routa PRIVATE routa_core)
target_include_directories(routa PRIVATE include)

# ── Examples ─────────────────────────────────────────────────────────────────
foreach(example hello_world)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}.c")
    add_executable(${example} examples/${example}.c)
    target_link_libraries(${example} PRIVATE routa_core)
    target_include_directories(${example} PRIVATE include)
  endif()
endforeach()

# ── Tests ────────────────────────────────────────────────────────────────────
foreach(test test_buf test_request test_middleware test_chunked test_file_cache test_ws test_config test_h2_hpack test_h2 test_auth test_metrics test_proxy_lb test_wrr_distribution test_real_world)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/${test}.c")
    add_executable(${test} tests/${test}.c)
    target_link_libraries(${test} PRIVATE routa_core)
    target_include_directories(${test} PRIVATE include)
  endif()
endforeach()

# ── Test helper binaries (not registered as ctest tests themselves --
# spawned as subprocesses by the tests that need them, e.g.
# test_real_world.c forking tests/helpers/real_world_server.c) ────────────
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/helpers/real_world_server.c")
    add_executable(real_world_server tests/helpers/real_world_server.c)
    target_link_libraries(real_world_server PRIVATE routa_core)
    target_include_directories(real_world_server PRIVATE include)
    # test_real_world.c needs to exec this binary by an absolute path --
    # it runs with WORKING_DIRECTORY set to the repo root (so its own
    # relative config/cert paths resolve correctly), but the binary
    # itself lives in the build directory, not the repo root. Bake the
    # actual build output path in as a compile definition rather than
    # guessing/hardcoding a build directory name (which varies: build_release,
    # build_asan, build_tsan, ... -- see the top-level Makefile's targets).
    if(TARGET test_real_world)
        target_compile_definitions(test_real_world PRIVATE
            REAL_WORLD_SERVER_PATH="$<TARGET_FILE:real_world_server>")
    endif()
endif()

# ── Bench server (tests/bench/bench_server.c) ────────────────────────────
# Not a ctest -- invoked manually by tests/bench/*.sh scripts. Config-driven
# (tests/bench/bench.conf) plus a WS echo route and a deliberately
# CPU-bound /api/cpu route, used to measure worker-blocking behavior under
# load (see PROJECT_SUMMARY / bench plan).
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/bench/bench_server.c")
    add_executable(bench_server tests/bench/bench_server.c)
    target_link_libraries(bench_server PRIVATE routa_core)
    target_include_directories(bench_server PRIVATE include)
endif()

# ── Fake site server (tests/fakesite/fakesite_server.c) ──────────────────
# Not a ctest -- a hands-on "host a real site" demo combining a static
# frontend, 3 proxy pools (fast/slow/flaky upstreams), a CPU-bound route,
# and a WS notifications route in one routa instance, to sanity-check
# everything fixed this session working together in a realistic setup.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fakesite/fakesite_server.c")
    add_executable(fakesite_server tests/fakesite/fakesite_server.c)
    target_link_libraries(fakesite_server PRIVATE routa_core)
    target_include_directories(fakesite_server PRIVATE include)
endif()

include(cmake/Sanitizers.cmake)

if(TARGET test_h2)
  target_link_libraries(test_h2 PRIVATE routa_core OpenSSL::SSL OpenSSL::Crypto pthread)
endif()

enable_testing()
add_test(NAME test_buf        COMMAND test_buf)
add_test(NAME test_request    COMMAND test_request)
add_test(NAME test_middleware COMMAND test_middleware)
add_test(NAME test_chunked    COMMAND test_chunked)
add_test(NAME test_file_cache    COMMAND test_file_cache)
add_test(NAME test_ws    COMMAND test_ws)
add_test(NAME test_h2_hpack    COMMAND test_h2_hpack)
add_test(NAME test_h2    COMMAND test_h2)
add_test(NAME test_auth    COMMAND test_auth)
add_test(NAME test_metrics   COMMAND test_metrics)
add_test(NAME test_proxy_lb   COMMAND test_proxy_lb WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME test_config   COMMAND test_config WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME test_wrr_distribution COMMAND test_wrr_distribution)
add_test(NAME test_real_world COMMAND test_real_world WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

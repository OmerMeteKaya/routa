cmake_minimum_required(VERSION 3.20)
project(routa VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(cmake/CompileFlags.cmake)

# ── Options ──────────────────────────────────────────────────────────────────
option(ROUTA_IO_URING "Use io_uring I/O backend (Linux only)" OFF)

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
        include/http/h2.h)

target_include_directories(routa_core PUBLIC include)

target_link_libraries(routa_core PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        ZLIB::ZLIB
)

# ── io_uring (Linux only, opt-in) ────────────────────────────────────────────
if(ROUTA_IO_URING)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "io_uring is Linux-only")
    endif()
    target_sources(routa_core PRIVATE src/net/uring.c)
    target_compile_definitions(routa_core PRIVATE ROUTA_IO_URING=1)
    target_link_libraries(routa_core PRIVATE uring)
endif()

# ── Examples ─────────────────────────────────────────────────────────────────
foreach(example hello_world config_example chunked_example ws_echo_server)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}.c")
        add_executable(${example} examples/${example}.c
                include/http/h2_hpack.h)
        target_link_libraries(${example} PRIVATE routa_core)
        target_include_directories(${example} PRIVATE include)
    endif()
endforeach()

# ── Tests ────────────────────────────────────────────────────────────────────
foreach(test test_buf test_request test_middleware test_chunked test_file_cache test_ws test_h2_hpack)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/${test}.c")
        add_executable(${test} tests/${test}.c)
        target_link_libraries(${test} PRIVATE routa_core)
        target_include_directories(${test} PRIVATE include)
    endif()
endforeach()

include(cmake/Sanitizers.cmake)

enable_testing()
add_test(NAME test_buf        COMMAND test_buf)
add_test(NAME test_request    COMMAND test_request)
add_test(NAME test_middleware COMMAND test_middleware)
add_test(NAME test_chunked    COMMAND test_chunked)
add_test(NAME test_file_cache    COMMAND test_file_cache)
add_test(NAME test_ws    COMMAND test_ws)
add_test(NAME test_h2_hpack    COMMAND test_h2_hpack)
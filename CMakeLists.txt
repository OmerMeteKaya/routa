cmake_minimum_required(VERSION 3.20)
project(routa VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(cmake/CompileFlags.cmake)

if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH
        "/opt/homebrew/opt/openssl@3"
        "/usr/local/opt/openssl@3")
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

file(GLOB_RECURSE ROUTA_SOURCES src/**/*.c)
add_library(routa_core STATIC ${ROUTA_SOURCES}
        include/http/mw_compress.h)
target_include_directories(routa_core PUBLIC include)
target_link_libraries(routa_core PUBLIC
    Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

add_executable(hello_world      examples/hello_world.c)
add_executable(config_example   examples/config_example.c)
add_executable(test_buf         tests/test_buf.c)
add_executable(test_request     tests/test_request.c)
add_executable(test_middleware  tests/test_middleware.c)

foreach(tgt hello_world config_example test_buf test_request test_middleware)
    target_link_libraries(${tgt} PRIVATE routa_core)
endforeach()

include(cmake/Sanitizers.cmake)

enable_testing()
add_test(NAME test_buf        COMMAND test_buf)
add_test(NAME test_request    COMMAND test_request)
add_test(NAME test_middleware COMMAND test_middleware)

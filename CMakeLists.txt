cmake_minimum_required(VERSION 3.20)
project(routa VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(cmake/CompileFlags.cmake)

file(GLOB_RECURSE ROUTA_SOURCES src/**/*.c)

add_library(routa_core STATIC ${ROUTA_SOURCES})
target_include_directories(routa_core PUBLIC include)

find_package(Threads REQUIRED)
target_link_libraries(routa_core PUBLIC Threads::Threads)

add_executable(hello_world examples/hello_world.c)
target_link_libraries(hello_world PRIVATE routa_core)

add_executable(test_buf tests/test_buf.c)
target_link_libraries(test_buf PRIVATE routa_core)

add_executable(test_request tests/test_request.c)
target_link_libraries(test_request PRIVATE routa_core)

# Sanitizers BURADA — tüm targetlar tanımlandıktan sonra
include(cmake/Sanitizers.cmake)

enable_testing()
add_test(NAME test_buf COMMAND test_buf)
add_test(NAME test_request COMMAND test_request)

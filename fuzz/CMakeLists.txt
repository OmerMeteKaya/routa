cmake_minimum_required(VERSION 3.20)

# Fuzzing targets — built separately from main build.
# Usage:
#   mkdir build_fuzz && cd build_fuzz
#   cmake .. -DFUZZ=ON -DCMAKE_C_COMPILER=clang
#   make fuzz_request fuzz_hpack fuzz_ws fuzz_h2_frame

option(FUZZ "Build libFuzzer targets" OFF)

if(FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "Fuzzing requires clang")
    endif()

    set(FUZZ_FLAGS -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
            -g -O1)

    foreach(TARGET fuzz_request fuzz_hpack fuzz_ws fuzz_h2_frame)
        add_executable(${TARGET} ${TARGET}.c)
        target_link_libraries(${TARGET} PRIVATE routa_core ssl crypto z)
        target_compile_options(${TARGET} PRIVATE ${FUZZ_FLAGS})
        target_link_options(${TARGET} PRIVATE ${FUZZ_FLAGS})
    endforeach()
endif()
cmake_minimum_required(VERSION 3.20)
if(NOT TARGET routa_core)
    message(FATAL_ERROR
            "fuzz targets must be built from the root CMakeLists.txt.\n"
            "Run: cmake -B build_afl -DROUTA_AFL=ON from the project root.")
endif()
option(FUZZ "Build libFuzzer fuzzers" OFF)
option(ROUTA_AFL "Build AFL++ fuzz targets" OFF)

if(FUZZ)

    set(FUZZ_TARGETS
            fuzz_request
            fuzz_hpack
            fuzz_ws
            fuzz_h2_frame
    )

    message(STATUS "Building libFuzzer fuzzers")

    foreach(TARGET ${FUZZ_TARGETS})
        add_executable(${TARGET} ${TARGET}.c)

        target_link_libraries(${TARGET}
                PRIVATE
                routa_core
                ssl
                crypto
                z
        )

        target_compile_options(${TARGET}
                PRIVATE
                -fsanitize=fuzzer,address,undefined
                -fno-omit-frame-pointer
                -g
                -O1
        )

        target_link_options(${TARGET}
                PRIVATE
                -fsanitize=fuzzer,address,undefined
        )
    endforeach()

endif()

if(ROUTA_AFL)
    find_program(AFL_CLANG afl-clang-fast)
    if(NOT AFL_CLANG)
        message(FATAL_ERROR "ROUTA_AFL=ON but afl-clang-fast not found")
    endif()
    set(AFL_TARGETS
            afl_fuzz_request
            afl_fuzz_hpack
            afl_fuzz_ws
            afl_fuzz_h2_frame
    )

    message(STATUS "Building AFL++ fuzz targets")

    # Verify afl-clang-fast is available
    find_program(AFL_CLANG afl-clang-fast REQUIRED)

    foreach(TARGET ${AFL_TARGETS})
        # Extract base name (e.g., afl_fuzz_request -> request)
        string(REPLACE "afl_fuzz_" "" BASE_NAME ${TARGET})

        add_executable(${TARGET} afl_fuzz_${BASE_NAME}.c fuzz_${BASE_NAME}.c)

        target_link_libraries(${TARGET}
                PRIVATE
                routa_core
                ssl
                crypto
                z
                pthread
        )

        target_compile_options(${TARGET}
                PRIVATE
                -O1
                -g
                -fsanitize=address,undefined
                -fno-omit-frame-pointer
        )

        target_link_options(${TARGET}
                PRIVATE
                -fsanitize=address,undefined
        )

        # Ensure AFL_USE_ASAN is set during compilation
        target_compile_definitions(${TARGET} PRIVATE AFL_USE_ASAN=1)
    endforeach()

endif()
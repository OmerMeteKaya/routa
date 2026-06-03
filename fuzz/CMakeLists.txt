cmake_minimum_required(VERSION 3.20)

option(FUZZ "Build fuzzers" OFF)
option(AFL "Build AFL++ fuzzers" OFF)

if(FUZZ)

    set(FUZZ_TARGETS
            fuzz_request
            fuzz_hpack
            fuzz_ws
            fuzz_h2_frame
    )

    if(AFL)

        message(STATUS "Building AFL++ fuzzers")

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
                    -O1
                    -g
                    -fsanitize=address
                    -fsanitize=undefined
                    -fno-omit-frame-pointer
            )

            target_link_options(${TARGET}
                    PRIVATE
                    -fsanitize=address
                    -fsanitize=undefined
            )
        endforeach()

    else()

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

endif()
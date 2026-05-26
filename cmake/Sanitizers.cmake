option(SANITIZERS "Enable ASAN + UBSAN" OFF)

if(SANITIZERS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(
                -fsanitize=address,undefined
                -fno-omit-frame-pointer
                -g
        )
        add_link_options(
                -fsanitize=address,undefined
        )
        message(STATUS "Sanitizers: ASAN + UBSAN enabled")
    else()
        message(WARNING "Sanitizers requested but compiler not supported")
    endif()
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND 
   CMAKE_SYSTEM_NAME STREQUAL "Linux" AND 
   CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(SAN_FLAGS -fsanitize=address,undefined)
    foreach(tgt routa_core hello_world test_buf test_request)
        target_compile_options(${tgt} PRIVATE ${SAN_FLAGS})
        target_link_options(${tgt} PRIVATE ${SAN_FLAGS})
    endforeach()
endif()

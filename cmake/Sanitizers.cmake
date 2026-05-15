if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND
        CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
        CMAKE_C_COMPILER_ID STREQUAL "GNU")

    set(SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)

    function(enable_sanitizers tgt)
        if(TARGET ${tgt})
            target_compile_options(${tgt} PRIVATE ${SAN_FLAGS})
            target_link_options(${tgt} PRIVATE ${SAN_FLAGS})
        endif()
    endfunction()

    get_property(all_targets DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY BUILDSYSTEM_TARGETS)
    foreach(tgt ${all_targets})
        enable_sanitizers(${tgt})
    endforeach()
endif()
###
# Enable compiler warnings
# Appends -Wall -Wextra flags to gcc and clang compiler options
#
function(target_enable_all_compiler_warnings target_name)
    if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

        if(NOT "${COMPILE_FLAGS}" MATCHES "-Wall")
            set_property(TARGET ${target_name}
                         APPEND_STRING PROPERTY COMPILE_FLAGS " -Wall" )
        endif()
        if(NOT "${COMPILE_FLAGS}" MATCHES "-Wextra")
            set_property(TARGET ${target_name}
                         APPEND_STRING PROPERTY COMPILE_FLAGS " -Wextra" )
        endif()
        if(NOT "${COMPILE_FLAGS}" MATCHES "-Wincompatible-pointer-types")
            # mips-linux-gcc-4.8.5 doesn't support this option
            if(NOT "${CMAKE_C_COMPILER}" MATCHES "mips")
                set_property(TARGET ${target_name}
                             APPEND_STRING PROPERTY COMPILE_FLAGS " -Wincompatible-pointer-types" )
            endif()
        endif()

    endif()
endfunction(target_enable_all_compiler_warnings)

###
# Disable deprecated declaration waring for gcc and clang
#
function(target_disable_deprecated_declarations_warning target_name)
    if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

        if(NOT "${COMPILE_FLAGS}" MATCHES "-Wno-deprecated-declarations")
            set_property(TARGET ${PROJECT_NAME}
                         APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-deprecated-declarations" )
        endif()
    endif()
endfunction(target_disable_deprecated_declarations_warning)

function(target_enable_memory_sanitizers target_name)
    if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

        if(NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=leak")
            if(NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=thread")
                set_property(TARGET ${target_name}
                             APPEND_STRING PROPERTY COMPILE_FLAGS " -fsanitize=leak -fno-omit-frame-pointer")
                set_property(TARGET ${target_name}
                             APPEND_STRING PROPERTY LINK_FLAGS " -fsanitize=leak")
            else()
                message(WARNING "-fsanitize=leak is incompatible with -fsanitize=thread")
            endif()
        endif()

        if(NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=address")
            if(NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=thread")
                set_property(TARGET ${target_name}
                            APPEND_STRING PROPERTY COMPILE_FLAGS " -fsanitize=address")
                set_property(TARGET ${target_name}
                             APPEND_STRING PROPERTY LINK_FLAGS " -fsanitize=address")
            else()
                message(WARNING "-fsanitize=address is incompatible with -fsanitize=thread")
            endif()
        endif()
    endif()
endfunction(target_enable_memory_sanitizers)

function(target_enable_thread_sanitizer target_name)
    if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
       "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
       "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

        if(NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=thread")
            if(NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=leak" AND NOT "${COMPILE_FLAGS}" MATCHES "-fsanitize=address")
                set_property(TARGET ${target_name}
                            APPEND_STRING PROPERTY COMPILE_FLAGS " -fsanitize=thread")
                set_property(TARGET ${target_name}
                             APPEND_STRING PROPERTY LINK_FLAGS " -fsanitize=thread")
            else()
                message(WARNING "-fsanitize=thread is incompatible with -fsanitize=address and -fsanitize=leak")
            endif()
        endif()
    endif()
endfunction(target_enable_thread_sanitizer)

function(target_enable_callstack_printing target_name)
    if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
            "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
            "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR
            "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")

        set_property(TARGET ${target_name}
            APPEND_STRING PROPERTY COMPILE_DEFINITIONS "IVESDK_ENABLE_CALLSTACK_PRINTING")
        set_property(TARGET ${target_name}
            APPEND_STRING PROPERTY LINK_FLAGS " -rdynamic")
    endif()
endfunction(target_enable_callstack_printing)

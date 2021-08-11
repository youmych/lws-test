cmake_minimum_required (VERSION 3.10)

project(lws-test LANGUAGES C)

set(SOURCES  
    src/minimal-ws-client.c
)

# Search our cmake-related tools into ./cmake directory                         
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")                      
                                                                                
# include tools                                                                 
include(ExternalProject)    # work with external projects                       
include(GNUInstallDirs)     # installation directories basic layout             
include(CMakePrintHelpers)  # cmake debug stuff                                 
include(compiler_options)   # our compiler stuff                                

add_executable(lws-test ${SOURCES})
add_executable(lws-json-parser src/json-parser.c)

set_target_properties(lws-test PROPERTIES
    C_STANDARD          99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        ON
)
set_target_properties(lws-json-parser PROPERTIES
    C_STANDARD          99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        ON
)
target_enable_all_compiler_warnings(lws-test)
target_enable_all_compiler_warnings(lws-json-parser)

# system libs
find_package(Threads REQUIRED)

set(THIRD_PARTY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install)

##### mbedtls ##################################################################
ExternalProject_Add(libmbedtls
    PREFIX thirdparty
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/thirdparty/mbedtls
    INSTALL_DIR ${THIRD_PARTY_INSTALL_DIR}
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
               -DENABLE_PROGRAMS=OFF
               -DENABLE_TESTING=OFF
               -DBUILD_SHARED_LIBS=OFF
               -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
)
ExternalProject_Get_Property(libmbedtls SOURCE_DIR INSTALL_DIR)
SET(SDK_MBEDTLS_DIR "${INSTALL_DIR}")
SET(SDK_MBEDTLS_INCLUDE_DIRS    "${INSTALL_DIR}/include")
SET(SDK_MBEDTLS_LIBRARY         "${INSTALL_DIR}/lib/libmbedtls.a")
SET(SDK_MBEDX509_LIBRARY        "${INSTALL_DIR}/lib/libmbedx509.a")
SET(SDK_MBEDCRYPTO_LIBRARY      "${INSTALL_DIR}/lib/libmbedcrypto.a")

message("SDK_MBEDTLS_INCLUDE_DIRS = ${SDK_MBEDTLS_INCLUDE_DIRS}")
message("SDK_MBEDTLS_LIBRARY = ${SDK_MBEDTLS_LIBRARY}")
message("SDK_MBEDX509_LIBRARY = ${SDK_MBEDX509_LIBRARY}")
message("SDK_MBEDCRYPTO_LIBRARY = ${SDK_MBEDCRYPTO_LIBRARY}")
add_library(mbedtls STATIC IMPORTED)
add_library(mbedx509 STATIC IMPORTED)
add_library(mbedcrypto STATIC IMPORTED)
set_property(TARGET mbedtls PROPERTY IMPORTED_LOCATION ${SDK_MBEDTLS_LIBRARY})
set_property(TARGET mbedx509 PROPERTY IMPORTED_LOCATION ${SDK_MBEDX509_LIBRARY})
set_property(TARGET mbedcrypto PROPERTY IMPORTED_LOCATION ${SDK_MBEDCRYPTO_LIBRARY})
################################################################################

##### libwebsockets ################################################################
ExternalProject_Add(libwebsockets
    PREFIX thirdparty
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/thirdparty/libwebsockets
    INSTALL_DIR ${THIRD_PARTY_INSTALL_DIR}
    DEPENDS mbedtls mbedx509 mbedcrypto
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
               -DBUILD_SHARED_LIBS=0
               -DLWS_WITH_SHARED=0
               -DLWS_WITH_STATIC=1
               -DLWS_STATIC_PIC=1
               -DLWS_UNIX_SOCK=1
               -DLWS_IPV6=1
               -DLWS_WITH_SERVER=1
               -DLWS_WITH_CLIENT=1
               -DLWS_WITH_HTTP_PROXY=1
               -DLWS_ROLE_RAW_PROXY=1
               -DLWS_ROLE_WS=1

               -DLWS_MAX_SMP=8

               -DLWS_WITH_HTTP_STREAM_COMPRESSION=0
               -DLWS_WITH_HTTP2=0
               -DLWS_WITH_CGI=0
               -DLWS_WITH_ZIP_FOPS=0
               -DLWS_WITH_ALSA=0
               -DLWS_WITH_THREADPOOL=0
               -DLWS_WITH_FTS=0
               -DLWS_ROLE_DBUS=0
               -DLWS_WITH_STRUCT_JSON=1
               -DLWS_WITH_LEJP_CONF=0

               -DDISABLE_WERROR=0               # set to 1 with libev
               -DLWS_WITH_LIBEV=0               # libev
               -DLWS_WITH_GLIB=0                # glib
               -DLWS_WITH_LIBUV=0               # libuv
               -DLWS_WITH_LIBEVENT=0            # libevent
               -DLWS_WITHOUT_TEST_APPS=1

               -DLWS_WITH_MBEDTLS=1
               -DLWS_MBEDTLS_INCLUDE_DIRS=${SDK_MBEDTLS_INCLUDE_DIRS}
               -DMBEDTLS_LIBRARY=${SDK_MBEDTLS_LIBRARY}
               -DMBEDX509_LIBRARY=${SDK_MBEDX509_LIBRARY}
               -DMBEDCRYPTO_LIBRARY=${SDK_MBEDCRYPTO_LIBRARY}

               -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
)
ExternalProject_Get_Property(libwebsockets SOURCE_DIR INSTALL_DIR)
set(PRO_LIBWEBSOCKETS_LIB "${INSTALL_DIR}/lib/libwebsockets.a")
add_library(websockets STATIC IMPORTED)
set_property(TARGET websockets PROPERTY IMPORTED_LOCATION ${PRO_LIBWEBSOCKETS_LIB})
################################################################################

target_include_directories(lws-test
    INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${THIRD_PARTY_INSTALL_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${THIRD_PARTY_INSTALL_DIR}/include>
)
target_include_directories(lws-json-parser
    INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${THIRD_PARTY_INSTALL_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${THIRD_PARTY_INSTALL_DIR}/include>
)

target_link_libraries(lws-test PUBLIC websockets mbedtls mbedx509 mbedcrypto pthread m dl)
target_link_libraries(lws-json-parser PUBLIC websockets mbedtls mbedx509 mbedcrypto pthread m dl)
add_dependencies(libwebsockets libmbedtls)
add_dependencies(lws-test libwebsockets)
add_dependencies(lws-json-parser libwebsockets)


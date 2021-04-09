cmake_minimum_required (VERSION 3.10)

project(lws-test LANGUAGES C)

set(SOURCES  
    src/minimal-http-client.c
)

# Search our cmake-related tools into ./cmake directory                         
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")                      
                                                                                
# include tools                                                                 
include(ExternalProject)    # work with external projects                       
include(GNUInstallDirs)     # installation directories basic layout             
include(CMakePrintHelpers)  # cmake debug stuff                                 
include(compiler_options)   # our compiler stuff                                

add_executable(lws-test ${SOURCES})

set_target_properties(lws-test PROPERTIES
    C_STANDARD          99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        ON
)
target_enable_all_compiler_warnings(lws-test)

# system libs
find_package(Threads REQUIRED)

set(THIRD_PARTY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install)

##### libwebsockets ################################################################
ExternalProject_Add(libwebsockets
    PREFIX thirdparty
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/thirdparty/libwebsockets
    INSTALL_DIR ${THIRD_PARTY_INSTALL_DIR}
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
               -DBUILD_SHARED_LIBS=0
               -DLWS_WITH_SHARED=0
               -DLWS_WITH_STATIC=1
               -DLWS_STATIC_PIC=1
               -DLWS_UNIX_SOCK=1                # required!
               -DLWS_IPV6=1
               -DLWS_WITH_SERVER=1
               -DLWS_WITH_CLIENT=1
               -DLWS_WITH_HTTP_PROXY=1
               -DLWS_ROLE_RAW_PROXY=1

               -DLWS_MAX_SMP=1

               -DLWS_WITH_HTTP_STREAM_COMPRESSION=0 # +deps libz
               -DLWS_WITH_HTTP2=0
               -DLWS_WITH_CGI=0
               -DLWS_WITH_ZIP_FOPS=0            # libz
               -DLWS_WITH_ALSA=0
               -DLWS_WITH_THREADPOOL=0
               -DLWS_WITH_FTS=0
               -DLWS_ROLE_DBUS=0                # dbus-related stuff
               -DLWS_WITH_LEJP_CONF=0

               -DDISABLE_WERROR=0               # set to 1 with libev
               -DLWS_WITH_LIBEV=0               # libev
               -DLWS_WITH_GLIB=0                # glib
               -DLWS_WITH_LIBUV=0               # libuv
               -DLWS_WITH_LIBEVENT=0            # libevent
               -DLWS_WITHOUT_TEST_APPS=1

               -DLWS_WITH_SSL=0
               -DLWS_WITH_TLS=0
               -DLWS_WITH_MBEDTLS=0
               -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
)
ExternalProject_Get_Property(libwebsockets SOURCE_DIR INSTALL_DIR)
set(SDK_LIBWEBSOCKETS_LIB "${INSTALL_DIR}/lib/libwebsockets.a")
add_library(websockets STATIC IMPORTED)
set_property(TARGET websockets PROPERTY IMPORTED_LOCATION ${SDK_LIBWEBSOCKETS_LIB})
################################################################################

target_include_directories(lws-test
    INTERFACE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${THIRD_PARTY_INSTALL_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${THIRD_PARTY_INSTALL_DIR}/include>
)

target_link_libraries(lws-test PUBLIC websockets pthread m)
add_dependencies(lws-test libwebsockets)


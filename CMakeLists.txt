cmake_minimum_required(VERSION 2.8)
project (pexrtmpserver)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_C_FLAGS "-std=c99 -Wall")

# GStreamer
find_package(GStreamer 0.10)
pkg_check_modules (GLIB2   glib-2.0)

add_library (pexrtmpserver SHARED amf.c client.c connections.c handshake.c rtmp.h rtmpserver.c utils.c)

include_directories(${GSTREAMER_INCLUDE_DIRS}
                    ${GLIB2_INCLUDE_DIRS})

target_link_libraries( pexrtmpserver ${GSTREAMER_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable ( rtmpserver main.c )
target_link_libraries( rtmpserver pexrtmpserver )

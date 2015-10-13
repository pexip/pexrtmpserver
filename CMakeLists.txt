cmake_minimum_required(VERSION 2.8)
project (pexrtmpserver)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_C_FLAGS "-std=c99 -Wall -Werror")

# GStreamer
find_package(GStreamer 0.10 REQUIRED)
add_definitions(${GSTREAMER_DEFINITIONS})

INCLUDE(FindPkgConfig)

PKG_CHECK_MODULES(PC_GSTREAMER gstreamer-0.10)
#MESSAGE(STATUS "DEBUG: GStreamer include directory = ${GSTREAMER_INCLUDE_DIRS}")
#MESSAGE(STATUS "DEBUG: GStreamer link directory = ${GSTREAMER_LIBRARY_DIRS}")
#MESSAGE(STATUS "DEBUG: GStreamer CFlags = ${GSTREAMER_CFLAGS_OTHER}") 
SET(GSTREAMER_DEFINITIONS ${PC_GSTREAMER_CFLAGS_OTHER})

FIND_PATH(GSTREAMER_INCLUDE_DIRS gst/gst.h
   PATHS
   ${PC_GSTREAMER_INCLUDEDIR}
   ${PC_GSTREAMER_INCLUDE_DIRS}
   #PATH_SUFFIXES gst
   )

FIND_LIBRARY(GSTREAMER_LIBRARIES NAMES gstreamer-0.10
   PATHS
   ${PC_GSTREAMER_LIBDIR}
   ${PC_GSTREAMER_LIBRARY_DIRS}
   )
pkg_check_modules (GLIB2   glib-2.0)

add_library (pexrtmpserver SHARED amf.c client.c connections.c handshake.c rtmp.h rtmpserver.c utils.c)

include_directories(${GSTREAMER_INCLUDE_DIRS}
                    ${GLIB2_INCLUDE_DIRS})
link_directories( ${GSTREAMER_LIBRARY_DIRS}
                  ${GLIB2_LIBRARY_DIRS})

target_link_libraries( pexrtmpserver ${GSTREAMER_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable ( rtmpserver main.c )
target_link_libraries( rtmpserver pexrtmpserver )

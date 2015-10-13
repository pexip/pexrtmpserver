# - Try to find GStreamer
# Once done this will define
#
#  GSTREAMER_FOUND - system has GStreamer
#  GSTREAMER_INCLUDE_DIRS - the GStreamer include directory
#  GSTREAMER_LIBRARIES - the libraries needed to use GStreamer
#  GSTREAMER_DEFINITIONS - Compiler switches required for using GStreamer
#  GSTREAMER_VERSION - the version of GStreamer

# Copyright (c) 2008, Helio Chissini de Castro, <helio@kde.org>
#           (c) 2006, Tim Beaulen <tbscope@gmail.com>
#           (c) 2013, Dirk Van Haerenborgh
find_package(PkgConfig)

# Helper macro to find a GStreamer plugin (or GStreamer itself)
#   _component_prefix is prepended to the _INCLUDE_DIRS and _LIBRARIES variables (eg. "GSTREAMER_AUDIO")
#   _pkgconfig_name is the component's pkg-config name (eg. "gstreamer-1.0", or "gstreamer-video-1.0").
#   _library is the component's library name (eg. "gstreamer-1.0" or "gstvideo-1.0")
macro(FIND_GSTREAMER_COMPONENT _component_prefix _pkgconfig_name _library)

    string(REGEX MATCH "(.*)>=(.*)" _dummy "${_pkgconfig_name}")
    if ("${CMAKE_MATCH_2}" STREQUAL "")
        pkg_check_modules(PC_${_component_prefix} "${_pkgconfig_name} >= ${GStreamer_FIND_VERSION}")
    else ()
        pkg_check_modules(PC_${_component_prefix} ${_pkgconfig_name})
    endif ()
    set(${_component_prefix}_INCLUDE_DIRS ${PC_${_component_prefix}_INCLUDE_DIRS})

    find_library(${_component_prefix}_LIBRARIES
        NAMES ${_library}
        HINTS ${PC_${_component_prefix}_LIBRARY_DIRS} ${PC_${_component_prefix}_LIBDIR}
    )
endmacro()

FIND_GSTREAMER_COMPONENT(GSTREAMER gstreamer-0.10 gstreamer-0.10)

mark_as_advanced(
    GSTREAMER_INCLUDE_DIRS
    GSTREAMER_LIBRARIES
)
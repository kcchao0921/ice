cmake_minimum_required(VERSION 2.8)
project(ice C)

find_library(GLIB libglib-2.0)

if(GLIB_FOUND)
message("found glib")
endif()

if(NOT DEFINED LOG_LEVEL)
    set(LOG_LEVEL "DEBUG")
endif()

add_definitions(
    -DLOG_LEVEL=LOG_LEVEL_${LOG_LEVEL}
)

add_library(ice SHARED
	src/ice.c
	src/stun.c
)

add_definitions(
    -D_GNU_SOURCE
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -O2")

include_directories(
    include
)

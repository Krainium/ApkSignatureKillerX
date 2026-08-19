cmake_minimum_required(VERSION 3.22.1)
project(demo C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
# Android 15+ (16 KB page size) alignment for our shared libs.
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

add_library(demo SHARED raw_syscall.c)

find_library(log-lib log)
target_link_libraries(demo ${log-lib})

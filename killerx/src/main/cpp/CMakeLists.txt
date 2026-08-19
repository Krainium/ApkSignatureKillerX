cmake_minimum_required(VERSION 3.22.1)
project(killerx C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
# Android 15+ (16 KB page size) alignment for our shared libs.
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

# ByteHook is delivered as a prefab package by the Gradle dependency.
find_package(bytehook REQUIRED CONFIG)

add_library(killerx SHARED
        killerx.c
        seccomp_trap.c
        svc_killer.c)

find_library(log-lib log)

target_link_libraries(killerx
        bytehook::bytehook
        ${log-lib})

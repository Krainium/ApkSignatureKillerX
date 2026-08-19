cmake_minimum_required(VERSION 3.18)
project(killerx_host C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# kx_adb: raw adb-protocol connection front end.
add_executable(kx_adb kx_adb.c adb_client.c)

# kx_probe: drive the demo over adb and grade the signature probes.
add_executable(kx_probe kx_probe.cpp adb_client.c)

# kx_seccomp_test: standalone proof that the seccomp openat trap redirects a
# DIRECT svc syscall (arm64). Runs on a real arm64 Linux kernel or inside redroid.
add_executable(kx_seccomp_test kx_seccomp_test.c)

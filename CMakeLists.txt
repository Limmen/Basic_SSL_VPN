cmake_minimum_required(VERSION 3.6)
project(vpn_lab)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES simpletun_encryption_udp/simpletun_encryption_udp.c)
add_executable(vpn_lab ${SOURCE_FILES})
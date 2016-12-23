cmake_minimum_required(VERSION 3.6)
project(vpnlab)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
    simpletun_encryption_udp/client.c
    simpletun_encryption_udp/client.h
    simpletun_encryption_udp/common.h
    simpletun_encryption_udp/parse_input.c
    simpletun_encryption_udp/parse_input.h
    simpletun_encryption_udp/server.c
    simpletun_encryption_udp/server.h
    simpletun_encryption_udp/simpletun_encryption_udp.c
    simpletun_encryption_udp/simpletun_encryption_udp.h
    simpletun_encryption_udp/ssl_util.c
    simpletun_encryption_udp/ssl_util.h
    simpletun_encryption_udp/tunnel_util.c
    simpletun_encryption_udp/tunnel_util.h
    simpletun_encryption_udp/util.c
    simpletun_encryption_udp/util.h)

add_executable(vpnlab ${SOURCE_FILES})
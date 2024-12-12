cmake_minimum_required(VERSION 3.28.3)
project(cryptography_game_util C)

set(CMAKE_C_STANDARD 11)

add_library(cryptography_game_util STATIC
        networking.c
        networking.h
        commands.c
        commands.h
        packet_parse_and_build.c
        packet_parse_and_build.h
        security.c
        security.h
)

add_executable(Test test.c)

target_link_libraries(Test cryptography_game_util)


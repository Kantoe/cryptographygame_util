cmake_minimum_required(VERSION 3.28.3)
project(cryptography_game_util C)

set(CMAKE_C_STANDARD 11)

add_library(cryptography_game_util STATIC
        cryptography_game_util.c
)

add_executable(Test test.c)

target_link_libraries(Test readline)


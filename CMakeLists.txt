cmake_minimum_required(VERSION 3.28.3)
project(cryptography_game_util C)

set(CMAKE_C_STANDARD 11)

# Add OpenSSL package finding
find_package(OpenSSL REQUIRED)

add_library(cryptography_game_util STATIC
        networking.c
        networking.h
        commands.c
        commands.h
        packet_parse_and_build.c
        packet_parse_and_build.h
        security.c
        security.h
        flag_file.c
        flag_file.h
        key_exchange.c
        key_exchange.h
        aes_encryption.c
        aes_encryption.h
)

# Link OpenSSL to your library
target_link_libraries(cryptography_game_util OpenSSL::Crypto)

add_executable(Test test.c)

# Link your library to the test executable
target_link_libraries(Test cryptography_game_util)
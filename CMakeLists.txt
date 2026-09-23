cmake_minimum_required(VERSION 3.20)

project(GyroJett-OneShot2
    VERSION 0.1.0
    DESCRIPTION "Privacy-focused terminal messenger"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(GyroJett-OneShot2
    src/main.c
    src/core/core.c
    src/cli/cli.c
    src/tor/tor.c
    src/server/server.c
    src/network/connection.c
    src/network/socks5.c
    src/client/client.c
    src/session/secret.c
)

target_include_directories(GyroJett-OneShot2 PRIVATE
    src
)

target_compile_options(GyroJett-OneShot2 PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(GyroJett-OneShot2 PRIVATE
        -g
        -O0
    )
else()
    target_compile_options(GyroJett-OneShot2 PRIVATE
        -O2
    )
endif()
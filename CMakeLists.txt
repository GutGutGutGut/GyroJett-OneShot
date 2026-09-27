cmake_minimum_required(VERSION 3.20)

project(GyroJett-OneShot2
VERSION 0.2.0
DESCRIPTION "Privacy-focused terminal messenger"
LANGUAGES C
)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

add_executable(GyroJett-OneShot2
src/main.c
src/core/core.c
src/cli/cli.c
src/tor/tor.c
src/server/server.c
src/network/connection.c
src/network/socks5.c
src/client/client.c
src/chat/chat.c
src/session/secret.c
src/session/auth.c
src/session/invite.c
src/crypto/crypto.c
src/crypto/x25519.c
src/crypto/mlkem.c
src/crypto/xeddsa.c
src/crypto/aead.c
src/identity/identity.c
src/handshake/pqxdh.c
src/protocol/frame.c
src/protocol/protocol.c
)

target_include_directories(GyroJett-OneShot2 PRIVATE
src
)

target_link_libraries(GyroJett-OneShot2 PRIVATE
OpenSSL::Crypto
xeddsa
)

target_compile_options(GyroJett-OneShot2 PRIVATE
-Wall
-Wextra
-Wpedantic
-Wconversion
-Wshadow
-fstack-protector-strong
-fstack-clash-protection

-D_FORTIFY_SOURCE=3

-Wformat
-Wformat-security

-fPIE

)

target_link_options(GyroJett-OneShot2 PRIVATE
-pie
-Wl,-z,relro
-Wl,-z,now
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

include(GNUInstallDirs)

install(
TARGETS GyroJett-OneShot2
RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

set(CPACK_GENERATOR "DEB")

set(CPACK_PACKAGE_NAME "gyrojett-oneshot")
set(CPACK_PACKAGE_VERSION "0.2.0-beta1")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
"Privacy-focused terminal messenger"
)
set(CPACK_PACKAGE_CONTACT "GutGutGutGut")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "GutGutGutGut")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_DEBIAN_PACKAGE_DEPENDS "tor")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include(CPack)

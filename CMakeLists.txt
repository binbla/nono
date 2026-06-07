cmake_minimum_required(VERSION 3.20)

project(nono
    VERSION 0.1.0
    LANGUAGES C CXX
)

option(NONO_BUILD_TESTS "Build nono test programs" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(NONO_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(NONO_INCLUDE_DIR "${NONO_ROOT_DIR}/include")
set(NONO_EXTERNAL_DIR "${NONO_ROOT_DIR}/external")

# -----------------------------------------------------------------------------
# System Dependencies
# -----------------------------------------------------------------------------

find_package(Threads REQUIRED)

find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY sodium)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Install libsodium-dev/libsodium-devel.")
endif()

add_library(Sodium::sodium UNKNOWN IMPORTED)
set_target_properties(Sodium::sodium PROPERTIES
    IMPORTED_LOCATION "${SODIUM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
)

# -----------------------------------------------------------------------------
# Third-party Modules
# -----------------------------------------------------------------------------

add_library(nono_blake2 STATIC
    external/BLAKE2/sse/blake2s.c
)
add_library(nono::blake2 ALIAS nono_blake2)
target_include_directories(nono_blake2
    PUBLIC
        "${NONO_EXTERNAL_DIR}/BLAKE2/sse"
)

add_library(nono_kcp STATIC
    external/kcp/ikcp.c
)
add_library(nono::kcp ALIAS nono_kcp)
target_include_directories(nono_kcp
    PUBLIC
        "${NONO_EXTERNAL_DIR}/kcp"
)

# -----------------------------------------------------------------------------
# Core Protocol Modules
# -----------------------------------------------------------------------------

add_library(nono_crypto STATIC
    src/crypto.cpp
)
add_library(nono::crypto ALIAS nono_crypto)
target_include_directories(nono_crypto
    PUBLIC
        "${NONO_INCLUDE_DIR}"
)
target_link_libraries(nono_crypto
    PUBLIC
        Sodium::sodium
    PRIVATE
        nono::blake2
)

add_library(nono_protocol STATIC
    src/noise.cpp
    src/protocol.cpp
    src/send.cpp
    src/receive.cpp
)
add_library(nono::protocol ALIAS nono_protocol)
target_include_directories(nono_protocol
    PUBLIC
        "${NONO_INCLUDE_DIR}"
)
target_link_libraries(nono_protocol
    PUBLIC
        nono::crypto
)

add_library(nono_core STATIC
    src/core.cpp
)
add_library(nono::core ALIAS nono_core)
target_include_directories(nono_core
    PUBLIC
        "${NONO_INCLUDE_DIR}"
)
target_link_libraries(nono_core
    PUBLIC
        nono::protocol
        Threads::Threads
)

# -----------------------------------------------------------------------------
# Reliable Layer
# -----------------------------------------------------------------------------

add_library(nono_reliable STATIC
    src/reliable.cpp
)
add_library(nono::reliable ALIAS nono_reliable)
target_include_directories(nono_reliable
    PUBLIC
        "${NONO_INCLUDE_DIR}"
)
target_link_libraries(nono_reliable
    PUBLIC
        nono::core
        nono::kcp
)

# Convenience target for applications that want the full stack.
add_library(nono_stack INTERFACE)
add_library(nono::stack ALIAS nono_stack)
target_link_libraries(nono_stack
    INTERFACE
        nono::reliable
)

# -----------------------------------------------------------------------------
# Test / Demo Programs
# -----------------------------------------------------------------------------

if(NONO_BUILD_TESTS)
    add_executable(nono_core_test
        src/core_test.cpp
    )
    target_link_libraries(nono_core_test
        PRIVATE
            nono::stack
    )

    add_executable(nono_echo_test
        src/echo_test.cpp
    )
endif()

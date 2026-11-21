cmake_minimum_required(VERSION 3.16)
project(NetworkTopologyMapper
    VERSION 1.0.0
    DESCRIPTION "Network Topology Mapper (NTM) - LAN Discovery and Evidence-Based Topology Inference CLI"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NTM_BUILD_TESTS "Build unit tests using GoogleTest" ON)
option(NTM_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

# Threads dependency
find_package(Threads REQUIRED)

# nlohmann_json dependency (prefer system package, fallback to FetchContent)
find_package(nlohmann_json 3.9.0 QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    message(STATUS "nlohmann_json not found via find_package; fetching v3.11.3...")
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# Core library (separates testable logic from main entrypoint)
set(NTM_CORE_SOURCES
    src/utils/logger.cpp
    src/utils/thread_pool.cpp
    src/utils/rate_limiter.cpp
    src/net/ip_address.cpp
    src/net/scope_validator.cpp
    src/net/interface_discovery.cpp
    src/discovery/packet_headers.cpp
    src/discovery/oui_lookup.cpp
    src/discovery/discovery_engine.cpp
    src/topology/topology_model.cpp
    src/topology/topology_inference.cpp
    src/export/exporter.cpp
    src/cli/cli_parser.cpp
)

add_library(ntm_core STATIC ${NTM_CORE_SOURCES})

target_include_directories(ntm_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(ntm_core
    PUBLIC
        Threads::Threads
        nlohmann_json::nlohmann_json
)

if(WIN32)
    target_link_libraries(ntm_core PUBLIC ws2_32 iphlpapi)
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(ntm_core PRIVATE /W4 /permissive-)
    if(NTM_WARNINGS_AS_ERRORS)
        target_compile_options(ntm_core PRIVATE /WX)
    endif()
else()
    target_compile_options(ntm_core PRIVATE -Wall -Wextra -Wpedantic)
    if(NTM_WARNINGS_AS_ERRORS)
        target_compile_options(ntm_core PRIVATE -Werror)
    endif()
endif()

# Main CLI Executable
add_executable(ntm src/main.cpp)
target_link_libraries(ntm PRIVATE ntm_core)

# Default data path definition
target_compile_definitions(ntm_core PUBLIC
    NTM_DEFAULT_OUI_PATH="${CMAKE_CURRENT_SOURCE_DIR}/data/oui.csv"
)

# Unit Tests
if(NTM_BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)
    if(NOT GTest_FOUND)
        include(FetchContent)
        message(STATUS "GTest not found via find_package; fetching googletest v1.14.0...")
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    add_executable(ntm_tests tests/test_main.cpp)
    target_link_libraries(ntm_tests
        PRIVATE
            ntm_core
            GTest::gtest
            GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(ntm_tests)
endif()

cmake_minimum_required(VERSION 3.15)
project(5g-anomaly-detector VERSION 1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add compile options
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/AnomalyDetector.cpp
    src/PacketProcessor.cpp
    src/NetworkMonitor.cpp
    src/AlertManager.cpp
)

# Create library
add_library(anomaly_lib ${SOURCES})
target_include_directories(anomaly_lib PUBLIC include)

# Main executable
add_executable(5g-anomaly-detector src/main.cpp)
target_link_libraries(5g-anomaly-detector anomaly_lib)

# Find required threads library
find_package(Threads REQUIRED)
target_link_libraries(anomaly_lib Threads::Threads)

# Testing
option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    # Download and configure Google Test
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    # Test executable
    add_executable(tests
        tests/test_PacketProcessor.cpp
        tests/test_AnomalyDetector.cpp
        tests/test_AlertManager.cpp
        tests/test_NetworkMonitor.cpp
    )

    target_link_libraries(tests
        anomaly_lib
        GTest::gtest_main
        GTest::gmock_main
    )

    include(GoogleTest)
    gtest_discover_tests(tests)
endif()

# Export compile commands for IntelliSense
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

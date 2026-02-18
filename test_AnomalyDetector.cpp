cmake_minimum_required(VERSION 3.15)
project(5g-anomaly-detector VERSION 1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
/**
 * @brief Enforces strict adherence to the specified C++ standard version.
 * 
 * When set to ON, this CMake property ensures that the compiler must support
 * the C++ standard version specified by CMAKE_CXX_STANDARD. If the compiler
 * does not support the required standard, the configuration will fail rather
 * than silently falling back to an older standard version.
 * 
 * @note This should be used in conjunction with CMAKE_CXX_STANDARD to guarantee
 *       that the project builds with the intended C++ standard features.
 */
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
        tests/test_NetworkMonitor.cpp  # ADAUGĂ ACEASTA
    )

    target_link_libraries(tests
        anomaly_lib
        GTest::gtest_main
        GTest::gmock_main
    )

    include(GoogleTest)
    gtest_discover_tests(tests)
endif()

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "AnomalyDetector.h"

using namespace anomaly;

class AnomalyDetectorTest : public ::testing::Test {
protected:
    std::unique_ptr<AnomalyDetector> detector;

    void SetUp() override {
        DetectorConfig config;
        config.max_latency_ms = 100.0;
        config.flood_threshold = 50;
        detector = std::make_unique<AnomalyDetector>(config);
    }
};

TEST_F(AnomalyDetectorTest, DetectsHighLatency) {
    Packet p("192.168.1.1", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 250.0);
    auto result = detector->analyze(p);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, AnomalyType::HIGH_LATENCY);
    EXPECT_EQ(result->source_ip, "192.168.1.1");
}

TEST_F(AnomalyDetectorTest, NormalLatencyNoAnomaly) {
    Packet p("192.168.1.1", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 50.0);
    auto result = detector->analyze(p);
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(AnomalyDetectorTest, DetectsFlood) {
    Packet p("192.168.1.10", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 10.0);
    
    for (int i = 0; i < 51; ++i) {
        auto result = detector->analyze(p);
        if (i >= 50) {
            ASSERT_TRUE(result.has_value());
            EXPECT_EQ(result->type, AnomalyType::FLOOD);
        }
    }
}

TEST_F(AnomalyDetectorTest, DetectsUnknownProtocol) {
    Packet p("192.168.1.1", "10.0.0.1", 5000, 9999, Protocol::UNKNOWN, 1024, 10.0);
    auto result = detector->analyze(p);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, AnomalyType::UNKNOWN_PROTOCOL);
}

TEST_F(AnomalyDetectorTest, AnalyzeBatchReturnsMultiple) {
    std::vector<Packet> packets = {
        Packet("192.168.1.1", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 250.0),
        Packet("192.168.1.2", "10.0.0.2", 6000, 80, Protocol::TCP, 512, 10.0),
        Packet("192.168.1.3", "10.0.0.3", 7000, 9999, Protocol::UNKNOWN, 256, 5.0)
    };
    
    auto reports = detector->analyzeBatch(packets);
    EXPECT_EQ(reports.size(), 2u);
}

TEST_F(AnomalyDetectorTest, ResetClearsState) {
    Packet p("192.168.1.10", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 10.0);
    
    for (int i = 0; i < 51; ++i) {
        detector->analyze(p);
    }
    
    detector->reset();
    
    auto result = detector->analyze(p);
    EXPECT_FALSE(result.has_value());
}

TEST_F(AnomalyDetectorTest, UpdateConfigChangesThresholds) {
    DetectorConfig new_config;
    new_config.max_latency_ms = 200.0;
    detector->updateConfig(new_config);
    
    Packet p("192.168.1.1", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 150.0);
    auto result = detector->analyze(p);
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(AnomalyDetectorTest, SeverityCalculation) {
    Packet p("192.168.1.1", "10.0.0.1", 5000, 80, Protocol::TCP, 1024, 250.0);
    auto result = detector->analyze(p);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->severity, 0.0);
    EXPECT_LE(result->severity, 1.0);
}

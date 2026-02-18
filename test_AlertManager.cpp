#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "AlertManager.h"
#include <filesystem>

using namespace anomaly;

class AlertManagerTest : public ::testing::Test {
protected:
    std::unique_ptr<AlertManager> manager;

    void SetUp() override {
        manager = std::make_unique<AlertManager>("test_alerts.log");
    }

    void TearDown() override {
        std::filesystem::remove("test_alerts.log");
        std::filesystem::remove("test_export.json");
    }

    AnomalyReport makeReport(AnomalyType type, double severity,
                              const std::string& ip = "192.168.1.1") {
        AnomalyReport r;
        r.type        = type;
        r.severity    = severity;
        r.source_ip   = ip;
        r.description = "Test anomaly";
        return r;
    }
};

TEST_F(AlertManagerTest, InitiallyEmpty) {
    EXPECT_EQ(manager->count(), 0u);
}

TEST_F(AlertManagerTest, RaiseAddsAlert) {
    manager->raise(makeReport(AnomalyType::HIGH_LATENCY, 0.5));
    EXPECT_EQ(manager->count(), 1u);
}

TEST_F(AlertManagerTest, ClearRemovesAllAlerts) {
    manager->raise(makeReport(AnomalyType::HIGH_LATENCY, 0.5));
    manager->raise(makeReport(AnomalyType::FLOOD, 0.9));
    manager->clearAlerts();
    EXPECT_EQ(manager->count(), 0u);
}

TEST_F(AlertManagerTest, CriticalSeverityMapsToCritical) {
    manager->raise(makeReport(AnomalyType::FLOOD, 0.9));
    auto criticals = manager->getAlertsByLevel(AlertLevel::CRITICAL);
    EXPECT_EQ(criticals.size(), 1u);
}

TEST_F(AlertManagerTest, LowSeverityMapsToLow) {
    manager->raise(makeReport(AnomalyType::UNKNOWN_PROTOCOL, 0.1));
    auto lows = manager->getAlertsByLevel(AlertLevel::LOW);
    EXPECT_EQ(lows.size(), 1u);
}

TEST_F(AlertManagerTest, FilterByLevelReturnsOnlyMatching) {
    manager->raise(makeReport(AnomalyType::HIGH_LATENCY, 0.5));  // MEDIUM
    manager->raise(makeReport(AnomalyType::FLOOD, 0.9));          // CRITICAL
    manager->raise(makeReport(AnomalyType::HIGH_LATENCY, 0.2));  // LOW

    auto mediums = manager->getAlertsByLevel(AlertLevel::MEDIUM);
    EXPECT_EQ(mediums.size(), 1u);
}

TEST_F(AlertManagerTest, ExportToJSONCreatesFile) {
    manager->raise(makeReport(AnomalyType::HIGH_LATENCY, 0.7));
    manager->exportToJSON("test_export.json");
    EXPECT_TRUE(std::filesystem::exists("test_export.json"));
}

TEST_F(AlertManagerTest, MultipleAlertsCountCorrectly) {
    for (int i = 0; i < 5; ++i) {
        manager->raise(makeReport(AnomalyType::HIGH_LATENCY, 0.5,
                                   "192.168.1." + std::to_string(i)));
    }
    EXPECT_EQ(manager->count(), 5u);
}

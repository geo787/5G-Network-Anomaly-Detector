#pragma once
#include "Packet.h"
#include <vector>
#include <string>
#include <mutex>
#include <fstream>

namespace anomaly {

enum class AlertLevel { LOW, MEDIUM, HIGH, CRITICAL };

struct Alert {
    AlertLevel level;
    std::string message;
    AnomalyReport report;
    std::string timestamp_str;
};

class AlertManager {
public:
    explicit AlertManager(const std::string& log_file = "alerts.log");
    ~AlertManager() = default;

    // Raise an alert from anomaly report
    void raise(const AnomalyReport& report);

    // Get all alerts raised so far
    const std::vector<Alert>& getAlerts() const { return alerts_; }

    // Get alerts filtered by level
    std::vector<Alert> getAlertsByLevel(AlertLevel level) const;

    // Export alerts to JSON file (for Python layer)
    void exportToJSON(const std::string& filepath) const;

    // Clear all alerts
    void clearAlerts();

    // Get alert count
    size_t count() const { return alerts_.size(); }

private:
    std::vector<Alert> alerts_;
    std::string log_file_;
    mutable std::mutex mtx_;

    AlertLevel severityToLevel(double severity) const;
    std::string levelToString(AlertLevel level) const;
    std::string getCurrentTimestamp() const;
    void writeToLog(const Alert& alert);
};

} // namespace anomaly

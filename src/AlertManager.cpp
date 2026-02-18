#include "AlertManager.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <chrono>
#include <ctime>

namespace anomaly {

AlertManager::AlertManager(const std::string& log_file)
    : log_file_(log_file) {}

void AlertManager::raise(const AnomalyReport& report) {
    std::lock_guard<std::mutex> lock(mtx_);

    Alert alert;
    alert.level         = severityToLevel(report.severity);
    alert.message       = report.description;
    alert.report        = report;
    alert.timestamp_str = getCurrentTimestamp();

    alerts_.push_back(alert);
    writeToLog(alert);

    // Print to console with level color hint
    std::cout << "[" << alert.timestamp_str << "] "
              << "[" << levelToString(alert.level) << "] "
              << alert.message << "\n";
}

std::vector<Alert> AlertManager::getAlertsByLevel(AlertLevel level) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<Alert> filtered;
    for (const auto& a : alerts_) {
        if (a.level == level) filtered.push_back(a);
    }
    return filtered;
}

void AlertManager::exportToJSON(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::ofstream file(filepath);
    if (!file.is_open()) return;

    file << "[\n";
    for (size_t i = 0; i < alerts_.size(); ++i) {
        const auto& a = alerts_[i];
        file << "  {\n"
             << "    \"timestamp\": \"" << a.timestamp_str << "\",\n"
             << "    \"level\": \""     << levelToString(a.level) << "\",\n"
             << "    \"message\": \""   << a.message << "\",\n"
             << "    \"source_ip\": \"" << a.report.source_ip << "\",\n"
             << "    \"severity\": "    << a.report.severity << "\n"
             << "  }" << (i + 1 < alerts_.size() ? "," : "") << "\n";
    }
    file << "]\n";
}

void AlertManager::clearAlerts() {
    std::lock_guard<std::mutex> lock(mtx_);
    alerts_.clear();
}

AlertLevel AlertManager::severityToLevel(double severity) const {
    if (severity >= 0.8) return AlertLevel::CRITICAL;
    if (severity >= 0.6) return AlertLevel::HIGH;
    if (severity >= 0.3) return AlertLevel::MEDIUM;
    return AlertLevel::LOW;
}

std::string AlertManager::levelToString(AlertLevel level) const {
    switch (level) {
        case AlertLevel::CRITICAL: return "CRITICAL";
        case AlertLevel::HIGH:     return "HIGH";
        case AlertLevel::MEDIUM:   return "MEDIUM";
        case AlertLevel::LOW:      return "LOW";
        default:                   return "UNKNOWN";
    }
}

std::string AlertManager::getCurrentTimestamp() const {
    auto now  = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void AlertManager::writeToLog(const Alert& alert) {
    std::ofstream file(log_file_, std::ios::app);
    if (!file.is_open()) return;
    file << "[" << alert.timestamp_str << "] "
         << "[" << levelToString(alert.level) << "] "
         << alert.message << "\n";
}

} // namespace anomaly

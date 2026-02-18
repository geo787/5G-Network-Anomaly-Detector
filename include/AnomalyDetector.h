#pragma once
#include "Packet.h"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <optional>

namespace anomaly {

struct DetectorConfig {
    double max_latency_ms{100.0};
    uint32_t flood_threshold{100};      // packets/sec from same IP
    double packet_loss_threshold{0.05}; // 5%
    uint32_t window_size_sec{10};       // sliding window
};

class AnomalyDetector {
public:
    explicit AnomalyDetector(DetectorConfig config = DetectorConfig{});
    ~AnomalyDetector() = default;

    // Analyze a single packet
    std::optional<AnomalyReport> analyze(const Packet& packet);

    // Analyze a batch — returns all detected anomalies
    std::vector<AnomalyReport> analyzeBatch(const std::vector<Packet>& packets);

    // Reset internal state (counters, history)
    void reset();

    // Get current config
    const DetectorConfig& getConfig() const { return config_; }

    // Update thresholds at runtime
    void updateConfig(const DetectorConfig& new_config);

private:
    DetectorConfig config_;
    std::unordered_map<std::string, uint32_t> packet_counts_;  // IP -> count
    std::unordered_map<std::string, uint32_t> sent_packets_;
    std::unordered_map<std::string, uint32_t> lost_packets_;
    mutable std::mutex mtx_;

    bool isHighLatency(const Packet& p) const;
    bool isFlood(const std::string& src_ip);
    bool isPacketLoss(const std::string& src_ip, uint32_t sent, uint32_t lost);
    double calculateSeverity(AnomalyType type, const Packet& p) const;
};

} // namespace anomaly

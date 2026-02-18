#include "AnomalyDetector.h"
#include <algorithm>

namespace anomaly {

AnomalyDetector::AnomalyDetector(DetectorConfig config)
    : config_(std::move(config)) {}

std::optional<AnomalyReport> AnomalyDetector::analyze(const Packet& packet) {
    std::lock_guard<std::mutex> lock(mtx_);

    if (isHighLatency(packet)) {
        AnomalyReport report;
        report.type        = AnomalyType::HIGH_LATENCY;
        report.source_ip   = packet.src_ip;
        report.description = "High latency detected: " +
                             std::to_string(packet.latency_ms) + " ms (threshold: " +
                             std::to_string(config_.max_latency_ms) + " ms)";
        report.severity    = calculateSeverity(AnomalyType::HIGH_LATENCY, packet);
        return report;
    }

    if (isFlood(packet.src_ip)) {
        AnomalyReport report;
        report.type        = AnomalyType::FLOOD;
        report.source_ip   = packet.src_ip;
        report.description = "Possible flood attack from " + packet.src_ip +
                             " (" + std::to_string(packet_counts_[packet.src_ip]) +
                             " packets)";
        report.severity    = calculateSeverity(AnomalyType::FLOOD, packet);
        return report;
    }

    if (packet.protocol == Protocol::UNKNOWN) {
        AnomalyReport report;
        report.type        = AnomalyType::UNKNOWN_PROTOCOL;
        report.source_ip   = packet.src_ip;
        report.description = "Unknown protocol on port " +
                             std::to_string(packet.dst_port);
        report.severity    = 0.3;
        return report;
    }

    return std::nullopt;
}

std::vector<AnomalyReport> AnomalyDetector::analyzeBatch(
    const std::vector<Packet>& packets) {
    std::vector<AnomalyReport> reports;
    for (const auto& pkt : packets) {
        auto result = analyze(pkt);
        if (result.has_value()) {
            reports.push_back(std::move(result.value()));
        }
    }
    return reports;
}

void AnomalyDetector::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    packet_counts_.clear();
    sent_packets_.clear();
    lost_packets_.clear();
}

void AnomalyDetector::updateConfig(const DetectorConfig& new_config) {
    std::lock_guard<std::mutex> lock(mtx_);
    config_ = new_config;
}

bool AnomalyDetector::isHighLatency(const Packet& p) const {
    return p.latency_ms > config_.max_latency_ms;
}

bool AnomalyDetector::isFlood(const std::string& src_ip) {
    auto& count = packet_counts_[src_ip];
    ++count;
    return count > config_.flood_threshold;
}

bool AnomalyDetector::isPacketLoss(const std::string& src_ip,
                                    uint32_t sent, uint32_t lost) {
    if (sent == 0) return false;
    double loss_rate = static_cast<double>(lost) / static_cast<double>(sent);
    return loss_rate > config_.packet_loss_threshold;
}

double AnomalyDetector::calculateSeverity(AnomalyType type,
                                           const Packet& p) const {
    switch (type) {
        case AnomalyType::HIGH_LATENCY: {
            double ratio = p.latency_ms / config_.max_latency_ms;
            return std::min(1.0, ratio / 10.0);
        }
        case AnomalyType::FLOOD: {
            double ratio = static_cast<double>(
                packet_counts_.count(p.src_ip) ? packet_counts_.at(p.src_ip) : 0)
                / static_cast<double>(config_.flood_threshold);
            return std::min(1.0, ratio / 2.0);
        }
        case AnomalyType::PACKET_LOSS:    return 0.6;
        case AnomalyType::UNKNOWN_PROTOCOL: return 0.3;
        default: return 0.0;
    }
}

} // namespace anomaly

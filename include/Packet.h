#pragma once
#include <string>
#include <cstdint>
#include <chrono>

namespace anomaly {

enum class Protocol { TCP, UDP, ICMP, UNKNOWN };
enum class AnomalyType { NONE, HIGH_LATENCY, PACKET_LOSS, FLOOD, UNKNOWN_PROTOCOL };

struct Packet {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    Protocol protocol{Protocol::UNKNOWN};
    uint32_t size_bytes{0};
    double latency_ms{0.0};
    std::chrono::system_clock::time_point timestamp;

    Packet() : timestamp(std::chrono::system_clock::now()) {}

    Packet(std::string src, std::string dst, uint16_t sport, uint16_t dport,
           Protocol proto, uint32_t size, double latency)
        : src_ip(std::move(src)), dst_ip(std::move(dst)),
          src_port(sport), dst_port(dport),
          protocol(proto), size_bytes(size), latency_ms(latency),
          timestamp(std::chrono::system_clock::now()) {}
};

struct AnomalyReport {
    AnomalyType type{AnomalyType::NONE};
    std::string description;
    std::string source_ip;
    double severity{0.0};  // 0.0 - 1.0
    std::chrono::system_clock::time_point detected_at;

    AnomalyReport() : detected_at(std::chrono::system_clock::now()) {}
};

} // namespace anomaly

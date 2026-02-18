#include "PacketProcessor.h"
#include <sstream>
#include <regex>
#include <stdexcept>

namespace anomaly {

PacketProcessor::PacketProcessor() = default;

Packet PacketProcessor::parsePacket(const std::string& raw_data) const {
    // Format: "src_ip:src_port->dst_ip:dst_port|size|latency"
    // Example: "192.168.1.1:5000->10.0.0.1:80|1024|12.5"
    Packet packet;
    try {
        std::istringstream ss(raw_data);
        std::string src_part, dst_part, size_str, latency_str;

        std::getline(ss, src_part, '-');
        std::string arrow;
        std::getline(ss, arrow, '>'); // consume '>'
        std::getline(ss, dst_part, '|');
        std::getline(ss, size_str, '|');
        std::getline(ss, latency_str);

        // Parse src
        auto src_colon = src_part.rfind(':');
        packet.src_ip   = src_part.substr(0, src_colon);
        packet.src_port = static_cast<uint16_t>(std::stoi(src_part.substr(src_colon + 1)));

        // Parse dst
        auto dst_colon = dst_part.rfind(':');
        packet.dst_ip   = dst_part.substr(0, dst_colon);
        packet.dst_port = static_cast<uint16_t>(std::stoi(dst_part.substr(dst_colon + 1)));

        packet.size_bytes = static_cast<uint32_t>(std::stoul(size_str));
        packet.latency_ms = std::stod(latency_str);
        packet.protocol   = detectProtocol(packet.dst_port);

    } catch (const std::exception&) {
        // Return empty packet on parse failure
        return Packet{};
    }
    return packet;
}

bool PacketProcessor::isValidPacket(const Packet& packet) const {
    if (packet.src_ip.empty() || packet.dst_ip.empty()) return false;
    if (!isValidIP(packet.src_ip) || !isValidIP(packet.dst_ip)) return false;
    if (packet.size_bytes == 0) return false;
    if (packet.latency_ms < 0.0) return false;
    return true;
}

Protocol PacketProcessor::detectProtocol(uint16_t port) const {
    switch (port) {
        case 80: case 443: case 8080: return Protocol::TCP;
        case 53: case 67:  case 68:   return Protocol::UDP;
        case 0:                        return Protocol::ICMP;
        default:
            if (port < 1024) return Protocol::TCP;
            return Protocol::UNKNOWN;
    }
}

void PacketProcessor::onPacketProcessed(PacketCallback callback) {
    callbacks_.push_back(std::move(callback));
}

std::vector<Packet> PacketProcessor::processBatch(
    const std::vector<std::string>& raw_packets) const {
    std::vector<Packet> result;
    result.reserve(raw_packets.size());
    for (const auto& raw : raw_packets) {
        auto pkt = parsePacket(raw);
        if (isValidPacket(pkt)) {
            result.push_back(pkt);
        }
    }
    return result;
}

bool PacketProcessor::isValidIP(const std::string& ip) const {
    static const std::regex ip_regex(
        R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    std::smatch match;
    if (!std::regex_match(ip, match, ip_regex)) return false;
    for (int i = 1; i <= 4; ++i) {
        int octet = std::stoi(match[i].str());
        if (octet < 0 || octet > 255) return false;
    }
    return true;
}

} // namespace anomaly

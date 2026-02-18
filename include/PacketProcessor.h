#pragma once
#include "Packet.h"
#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace anomaly {

class PacketProcessor {
public:
    using PacketCallback = std::function<void(const Packet&)>;

    PacketProcessor();
    ~PacketProcessor() = default;

    // Disable copy, allow move
    PacketProcessor(const PacketProcessor&) = delete;
    PacketProcessor& operator=(const PacketProcessor&) = delete;
    PacketProcessor(PacketProcessor&&) = default;
    PacketProcessor& operator=(PacketProcessor&&) = default;

    // Parse raw packet data into Packet struct
    Packet parsePacket(const std::string& raw_data) const;

    // Validate packet fields
    bool isValidPacket(const Packet& packet) const;

    // Protocol detection from port number
    Protocol detectProtocol(uint16_t port) const;

    // Register callback for processed packets
    void onPacketProcessed(PacketCallback callback);

    // Process a batch of raw packets
    std::vector<Packet> processBatch(const std::vector<std::string>& raw_packets) const;

private:
    std::vector<PacketCallback> callbacks_;
    bool isValidIP(const std::string& ip) const;
};

} // namespace anomaly

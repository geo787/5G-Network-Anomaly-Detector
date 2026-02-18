#include "NetworkMonitor.h"
#include <random>
#include <iostream>
#include <chrono>

namespace anomaly {

NetworkMonitor::NetworkMonitor(std::shared_ptr<AnomalyDetector> detector,
                               std::shared_ptr<AlertManager> alert_manager)
    : detector_(std::move(detector))
    , alert_manager_(std::move(alert_manager)) {}

NetworkMonitor::~NetworkMonitor() {
    stop();
}

void NetworkMonitor::start() {
    running_.store(true);
    monitor_thread_ = std::thread(&NetworkMonitor::processLoop, this);
    std::cout << "[NetworkMonitor] Started monitoring thread.\n";
}

void NetworkMonitor::stop() {
    if (running_.load()) {
        running_.store(false);
        cv_.notify_all();
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
        std::cout << "[NetworkMonitor] Monitoring stopped.\n";
    }
}

void NetworkMonitor::feedPacket(const Packet& packet) {
    {
        std::lock_guard<std::mutex> lock(queue_mtx_);
        packet_queue_.push(packet);
    }
    cv_.notify_one();
}

void NetworkMonitor::simulateTraffic(int num_packets) {
    std::cout << "[NetworkMonitor] Simulating " << num_packets
              << " 5G network packets...\n";
    for (int i = 0; i < num_packets; ++i) {
        bool inject_anomaly = (i % 10 == 0); // every 10th packet is anomalous
        feedPacket(generateSimulatedPacket(inject_anomaly));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void NetworkMonitor::processLoop() {
    while (running_.load()) {
        std::unique_lock<std::mutex> lock(queue_mtx_);
        cv_.wait(lock, [this] {
            return !packet_queue_.empty() || !running_.load();
        });

        while (!packet_queue_.empty()) {
            Packet pkt = packet_queue_.front();
            packet_queue_.pop();
            lock.unlock();

            auto anomaly = detector_->analyze(pkt);
            if (anomaly.has_value()) {
                alert_manager_->raise(anomaly.value());
            }

            lock.lock();
        }
    }
}

Packet NetworkMonitor::generateSimulatedPacket(bool inject_anomaly) const {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<> ip_dist(1, 254);
    static std::uniform_int_distribution<> port_dist(1024, 9999);
    static std::uniform_int_distribution<> size_dist(64, 1500);
    static std::uniform_real_distribution<> latency_dist(1.0, 50.0);

    std::string src_ip = "192.168." + std::to_string(ip_dist(rng)) +
                         "." + std::to_string(ip_dist(rng));
    std::string dst_ip = "10.0." + std::to_string(ip_dist(rng)) +
                         "." + std::to_string(ip_dist(rng));

    double latency = inject_anomaly ? 250.0 + latency_dist(rng)  // anomalous
                                    : latency_dist(rng);           // normal

    return Packet(
        src_ip, dst_ip,
        static_cast<uint16_t>(port_dist(rng)),
        80,
        Protocol::TCP,
        static_cast<uint32_t>(size_dist(rng)),
        latency
    );
}

} // namespace anomaly

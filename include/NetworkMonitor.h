#pragma once
#include "PacketProcessor.h"
#include "AnomalyDetector.h"
#include "AlertManager.h"
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

namespace anomaly {

/// @brief 
class NetworkMonitor {
public:
    NetworkMonitor(std::shared_ptr<AnomalyDetector> detector,
                   std::shared_ptr<AlertManager> alert_manager);
    ~NetworkMonitor();

    // Start monitoring in background thread
    void start();

    // Stop monitoring gracefully
    void stop();

    // Feed a packet into the processing queue
    void feedPacket(const Packet& packet);

    // Feed simulated 5G traffic (for demo/testing)
    void simulateTraffic(int num_packets = 50);

    bool isRunning() const { return running_.load(); }

private:
    std::shared_ptr<AnomalyDetector> detector_;
    std::shared_ptr<AlertManager> alert_manager_;

    std::queue<Packet> packet_queue_;
    std::mutex queue_mtx_;
    std::condition_variable cv_;

    std::thread monitor_thread_;
    std::atomic<bool> running_{false};

    void processLoop();
    Packet generateSimulatedPacket(bool inject_anomaly = false) const;
};

} // namespace anomaly

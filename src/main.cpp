#include "NetworkMonitor.h"
#include "AnomalyDetector.h"
#include "AlertManager.h"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

int main() {
    std::cout << "=== 5G Network Anomaly Detector ===\n\n";

    // Configure detector thresholds
    anomaly::DetectorConfig config;
    config.max_latency_ms      = 100.0;
    config.flood_threshold     = 50;
    config.packet_loss_threshold = 0.05;

    auto detector      = std::make_shared<anomaly::AnomalyDetector>(config);
    auto alert_manager = std::make_shared<anomaly::AlertManager>("alerts.log");
    auto monitor       = std::make_unique<anomaly::NetworkMonitor>(
                             detector, alert_manager);

    // Start background monitoring thread
    monitor->start();

    // Simulate 5G network traffic
    monitor->simulateTraffic(50);

    // Wait for processing to complete
    std::this_thread::sleep_for(std::chrono::seconds(2));

    monitor->stop();

    // Export results for Python analysis layer
    alert_manager->exportToJSON("alerts.json");

    std::cout << "\n=== Summary ===\n";
    std::cout << "Total alerts raised: " << alert_manager->count() << "\n";
    std::cout << "Results exported to alerts.json\n";
    std::cout << "Run python/analyze.py for visualization.\n";

    return 0;
}

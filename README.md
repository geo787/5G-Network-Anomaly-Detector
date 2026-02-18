# 5G Network Anomaly Detector

A high-performance network anomaly detection system for 5G/6G environments, built with **C++17** and **Python**.  
Demonstrates real-world software engineering practices aligned with Nokia's R&D 5G stack.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  C++ Core Engine                    │
│  ┌──────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │PacketProcessor│→│AnomalyDetect│→│AlertManager│  │
│  └──────────────┘  └─────────────┘  └───────────┘  │
│           NetworkMonitor (multithreaded)             │
└─────────────────────┬───────────────────────────────┘
                      │ alerts.json
┌─────────────────────▼───────────────────────────────┐
│              Python Analysis Layer                  │
│         analyze.py → anomaly_dashboard.png          │
└─────────────────────────────────────────────────────┘
```

## Features

- **C++17** with smart pointers, move semantics, `std::optional`, `std::thread`
- **Multithreaded** packet processing with producer/consumer pattern
- **Anomaly detection**: High latency, flood attacks, packet loss, unknown protocols
- **Google Test (GTest + GMock)** — full unit test coverage
- **CI/CD pipeline** via GitHub Actions
- **Docker** multi-stage build
- **Python** visualization layer with Matplotlib dashboard

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Core Engine | C++17, STL, std::thread, std::mutex |
| Testing | Google Test, Google Mock |
| Build | CMake 3.14+, Ninja |
| CI/CD | GitHub Actions |
| Container | Docker (multi-stage) |
| Analysis | Python 3.11, Matplotlib |

## Project Structure

```
5g-anomaly-detector/
├── include/
│   ├── Packet.h           # Core data structures
│   ├── PacketProcessor.h  # Packet parsing & validation
│   ├── AnomalyDetector.h  # Detection logic
│   ├── NetworkMonitor.h   # Multithreaded monitor
│   └── AlertManager.h     # Alert management & export
├── src/
│   ├── PacketProcessor.cpp
│   ├── AnomalyDetector.cpp
│   ├── NetworkMonitor.cpp
│   ├── AlertManager.cpp
│   └── main.cpp
├── tests/
│   ├── test_PacketProcessor.cpp
│   ├── test_AnomalyDetector.cpp
│   └── test_AlertManager.cpp
├── python/
│   └── analyze.py         # Visualization dashboard
├── .github/workflows/
│   └── ci.yml             # CI pipeline
├── Dockerfile
└── CMakeLists.txt
```

## Build & Run

### Prerequisites
- CMake 3.14+
- C++17 compiler (GCC 9+ / MSVC 2019+)
- Python 3.11+ with `matplotlib`

### Build
```bash
cmake -B build -DCMAKE_CXX_STANDARD=17
cmake --build build
```

### Run
```bash
./build/anomaly_detector
```

### Run Tests
```bash
cd build && ctest --output-on-failure
```

### Python Dashboard
```bash
pip install matplotlib
python python/analyze.py
```

### Docker
```bash
docker build -t 5g-anomaly-detector .
docker run 5g-anomaly-detector
```

## Anomaly Types Detected

| Type | Description | Severity |
|------|-------------|----------|
| HIGH_LATENCY | Packet latency exceeds threshold (default: 100ms) | Dynamic |
| FLOOD | Excessive packets from single IP | Dynamic |
| PACKET_LOSS | Loss rate exceeds 5% | 0.6 |
| UNKNOWN_PROTOCOL | Unrecognized protocol/port | 0.3 |

## Configuration

```cpp
DetectorConfig config;
config.max_latency_ms       = 100.0;  // ms
config.flood_threshold      = 50;     // packets/window
config.packet_loss_threshold = 0.05;  // 5%
config.window_size_sec      = 10;     // sliding window
```

---

*Built by Roberta Barba — Cybersecurity Analyst & Python Developer*  
*LinkedIn: linkedin.com/in/roberta-barba-5b99261b5*

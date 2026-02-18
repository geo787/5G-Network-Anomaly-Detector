# API Documentation

## PacketProcessor

### `parsePacket(const std::string& raw_data)`
Parses raw packet string in format: `src_ip:port->dst_ip:port|size|latency`

### `isValidPacket(const Packet& packet)`
Validates packet fields (IP format, non-zero size, positive latency)

## AnomalyDetector

### `analyze(const Packet& packet)`
Analyzes single packet, returns `std::optional<AnomalyReport>`

### Thresholds
- `max_latency_ms`: 100.0 ms (default)
- `flood_threshold`: 50 packets/window
- `packet_loss_threshold`: 5%
# Stage 1: Build C++ engine
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    cmake g++ ninja-build git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=17 \
    && cmake --build build

# Stage 2: Runtime + Python
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install matplotlib

WORKDIR /app

# Copy C++ binary from builder
COPY --from=builder /app/build/anomaly_detector .

# Copy Python analysis layer
COPY python/ ./python/

# Run C++ engine then Python analysis
CMD ["sh", "-c", "./anomaly_detector && python python/analyze.py"]

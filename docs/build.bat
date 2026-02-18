@echo off
echo Building 5G Anomaly Detector...
mkdir build 2>nul
cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build .
echo Build complete!
pause
#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <regex>

#define CRSF_CHANNEL_VALUE_MIN 172
#define CRSF_CHANNEL_VALUE_1000 191
#define CRSF_CHANNEL_VALUE_MID 992
#define CRSF_CHANNEL_VALUE_2000 1792
#define CRSF_CHANNEL_VALUE_MAX 1811

struct NetworkUsage;
NetworkUsage getNetworkUsage();
int getCpuTemperature();
void getSignalStrength(int& rssi, int& snr);
std::string getServingCellInfo() ;
int16_t CRC16(uint16_t* data, size_t length);
uint8_t CRC8(const uint8_t* data, size_t start, size_t length);

// Lightweight logger. File mode writes to LOG_DIR/masina_<date>_<time>.log, opened on the first
// File log and only if LOG_DIR is a mounted rw filesystem (SD card); opening is attempted once.
// The file is size-capped and rotated once (<path>.1). No heap allocation per entry.
#define LOG_DIR "/mnt/mmcblk0p1"
#define LOG_MAX_BYTES (256 * 1024)

enum class DebugMsgMode : uint8_t
{
    Disabled = 0,
    Console = 1, // stdout, no timestamp
    File = 2,    // timestamped lines in the log file
};

void Log(uint8_t mode, const char* msg, size_t len);
inline void Log(uint8_t mode, const char* msg)
{
    Log(mode, msg, strlen(msg));
}

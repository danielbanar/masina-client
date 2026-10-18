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
#include <netinet/in.h>

#define CRSF_CHANNEL_VALUE_MIN 172
#define CRSF_CHANNEL_VALUE_1000 191
#define CRSF_CHANNEL_VALUE_MID 992
#define CRSF_CHANNEL_VALUE_2000 1792
#define CRSF_CHANNEL_VALUE_MAX 1811

// Interface byte counters; 64-bit because the kernel counters pass 4 GiB
struct NetworkUsage
{
    uint64_t rxBytes;
    uint64_t txBytes;
};

// Cumulative CPU time of one core in jiffies from /proc/stat; usage is the busy share of the difference between two samples
struct CpuTimes
{
    uint64_t total;
    uint64_t idle;
    bool present; // listed in /proc/stat, i.e. the core exists and is online
};

struct MemoryUsage
{
    uint32_t usedMB; // MemTotal - MemAvailable, so reclaimable page cache is not counted
    uint32_t totalMB;
};

int initializeSocket(const std::string& address, int port, struct sockaddr_in& serverAddr);
NetworkUsage getNetworkUsage();
int getCpuTemperature();
void getCpuTimes(CpuTimes* cores, int maxCores);
MemoryUsage getMemoryUsage();
void getSignalStrength(int& rssi, int& snr);
int16_t CRC16(uint16_t* data, size_t length);
uint8_t CRC8(const uint8_t* data, size_t start, size_t length);

// Lightweight logger. File mode writes to LOG_DIR/masina_<date>_<time>.log, opened on the first
// File log and only if LOG_DIR is a mounted rw filesystem (SD card); opening is attempted once.
// The file is never truncated or rotated. No heap allocation per entry.
#define LOG_DIR "/mnt/mmcblk0p1"

void Log(uint8_t mode, const char* msg, size_t len);
inline void Log(uint8_t mode, const char* msg)
{
    Log(mode, msg, strlen(msg));
}

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
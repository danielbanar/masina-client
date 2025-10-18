#pragma once

#include <cstdint>
#include <map>
#include <string>

struct Config
{
    uint32_t localTimeout = 300000;
    uint32_t failsafeTimeout = 5000;
    uint32_t stabTimeout = 250;
    uint32_t elrsSwitchPin = 1;
    uint32_t hoverValue = 1200;
    std::string groundIP;
    uint32_t rcChannels = 12;
    std::string serialPort = "/dev/ttyS2";

    bool readConfig(const std::string& filename);
    void print() const;
};
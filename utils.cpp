#include "utils.h"
#include "config.h"

Config config;

void Config::print() const
{
    std::cout << "Configuration:" << std::endl;
    std::cout << "  localTimeout: " << localTimeout << std::endl;
    std::cout << "  failsafeTimeout: " << failsafeTimeout << std::endl;
    std::cout << "  stabTimeout: " << stabTimeout << std::endl;
    std::cout << "  elrsSwitchPin: " << elrsSwitchPin << std::endl;
    std::cout << "  hoverValue: " << hoverValue << std::endl;
    std::cout << "  groundIP: " << groundIP << std::endl;
    std::cout << "  rcChannels: " << rcChannels << std::endl;
    std::cout << "  serialPort: " << serialPort << std::endl;
    std::cout << "  debug: " << debug << std::endl;
}

bool Config::readConfig(const std::string& filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "Failed to open config file: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value))
        {
            if (key == "GROUND_IP")
                groundIP = value;
            else if (key == "LOCAL_TIMEOUT")
                localTimeout = std::stoi(value);
            else if (key == "FAILSAFE_TIMEOUT")
                failsafeTimeout = std::stoi(value);
            else if (key == "STABILIZE_TIMEOUT")
                stabTimeout = std::stoi(value);
            else if (key == "ELRS_SWITCH_PIN")
                elrsSwitchPin = std::stoi(value);
            else if (key == "HOVER_VALUE")
                hoverValue = std::stoi(value);
            else if (key == "RC_CHANNELS")
                rcChannels = std::stoi(value);
            else if (key == "SERIAL_PORT")
                serialPort = value;
            else if (key == "DEBUG")
                debug = std::stoi(value);
        }
    }
    return true;
}

struct NetworkUsage
{
    unsigned long rxBytes;
    unsigned long txBytes;
};

NetworkUsage getNetworkUsage()
{
    std::ifstream netDevFile("/proc/net/dev");
    std::string line;
    NetworkUsage usage = {0, 0};

    // Skip the first two lines (header lines)
    std::getline(netDevFile, line);
    std::getline(netDevFile, line);

    while (std::getline(netDevFile, line))
    {
        std::istringstream iss(line);
        std::string iface;
        iss >> iface;

        // Remove trailing colon from the interface name
        if (!iface.empty() && iface.back() == ':')
            iface.pop_back();

        if (iface == "usb0")
        {
            unsigned long rx_bytes, dummy, tx_bytes;

            iss >> rx_bytes; // receive bytes

            // Skip the next 7 fields (packets, errs, drop, fifo, frame, compressed, multicast)
            for (int i = 0; i < 7; ++i)
                iss >> dummy;

            iss >> tx_bytes; // transmit bytes

            usage.rxBytes = rx_bytes;
            usage.txBytes = tx_bytes;
            break;
        }
    }

    return usage;
}

int getCpuTemperature()
{
    std::ifstream file("/sys/devices/virtual/mstar/msys/TEMP_R");
    if (!file.is_open())
    {
        std::cerr << "Error: Unable to open temperature file." << std::endl;
        return -1;
    }

    std::string line;
    std::getline(file, line);
    file.close();

    size_t pos = line.find("Temperature ");
    if (pos == std::string::npos)
    {
        std::cerr << "Error: Unexpected file format." << std::endl;
        return -1;
    }

    try
    {
        int temperature = std::stoi(line.substr(pos + 12)); // Extract temperature after "Temperature "
        return temperature;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: Failed to parse temperature: " << e.what() << std::endl;
        return -1;
    }
}

void getSignalStrength(int& rssi, int& snr)
{
    const char* command = "qmicli --device=/dev/cdc-wdm0 --nas-get-signal-strength";

    FILE* fp = popen(command, "r");
    if (fp == nullptr)
    {
        std::cerr << "Failed to run command" << std::endl;
        rssi = -1; // Return -1 if command fails
        snr = -1;  // Return -1 if command fails
        return;
    }

    char buffer[256];
    std::string output;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr)
    {
        output += buffer;
    }
    std::cout << buffer;
    fclose(fp);

    std::cout << "Command Output:\n" << output << std::endl;

    std::regex rssiRegex("RSSI:\\s*.*?([-\\d]+) dBm");
    std::regex snrRegex("SNR:\\s*.*?([\\d\\.]+) dB");
    std::smatch match;

    if (std::regex_search(output, match, rssiRegex) && match.size() > 1)
    {
        rssi = std::stoi(match[1].str());
    }
    else
    {
        std::cerr << "Failed to parse RSSI" << std::endl;
        rssi = -1;
    }

    if (std::regex_search(output, match, snrRegex) && match.size() > 1)
    {
        snr = static_cast<int>(std::stof(match[1].str()));
    }
    else
    {
        std::cerr << "Failed to parse SNR" << std::endl;
        snr = -1;
    }
}
std::string getServingCellInfo()
{
    return "";
    // Command to send AT command and read response from /dev/ttyUSB2
    const char* command = "at_command";

    // Open a pipe to execute the command
    FILE* fp = popen(command, "r");
    if (fp == nullptr)
    {
        std::cerr << "Failed to run command" << std::endl;
        return "";
    }

    // Read the output of the command
    char buffer[256];
    std::string output;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr)
    {
        output += buffer;
    }

    // Close the pipe
    pclose(fp);

    return output;
}

int16_t CRC16(uint16_t* data, size_t length)
{
    uint16_t crc = 0x0000;        // Initial value
    uint16_t polynomial = 0x1021; // Polynomial for CRC-16-CCITT

    for (size_t i = 0; i < length; ++i)
    {
        uint16_t current_data = data[i];
        for (size_t j = 0; j < 16; ++j)
        {
            bool bit = (current_data >> (15 - j) & 1) ^ ((crc >> 15) & 1);
            crc <<= 1;
            if (bit)
            {
                crc ^= polynomial;
            }
        }
    }

    return crc;
}
uint8_t CRC8(const uint8_t* data, size_t start, size_t length)
{
    uint8_t crc = 0;
    size_t end = start + length;

    for (std::size_t i = start; i < end; ++i)
    {
        crc ^= data[i];

        for (uint8_t j = 0; j < 8; ++j)
        {
            if (crc & 0x80)
                crc = (crc << 1) ^ 0xD5;
            else
                crc <<= 1;
        }
    }

    return crc;
}

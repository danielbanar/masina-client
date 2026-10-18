#include "utils.h"
#include "config.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mntent.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

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
                // debug 0: off, 1: console, 2+: file (opened on the first log)
        }
    }
    return true;
}

int initializeSocket(const std::string& address, int port, struct sockaddr_in& serverAddr)
{
    int sockfd;
    struct addrinfo hints, *res;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;      // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP

    // Check if the input is an IP address
    if (inet_pton(AF_INET, address.c_str(), &serverAddr.sin_addr) == 1)
    {
        // It's an IP address
        serverAddr.sin_family = AF_INET;
    }
    else
    {
        // It's a hostname, resolve it
        if (getaddrinfo(address.c_str(), NULL, &hints, &res) != 0)
        {
            perror("getaddrinfo failed");
            exit(EXIT_FAILURE);
        }

        // Copy the resolved address to serverAddr
        serverAddr = *(struct sockaddr_in*)(res->ai_addr);
        freeaddrinfo(res);
    }

    serverAddr.sin_port = htons(port);

    // Set socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    return sockfd;
}

// Reads a single unsigned number from a sysfs file
static bool readU64(const char* path, uint64_t& value)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return false;
    buf[n] = '\0';
    value = strtoull(buf, nullptr, 10);
    return true;
}

NetworkUsage getNetworkUsage()
{
    NetworkUsage usage = {0, 0};
    for (const char* iface : {"usb0", "wwan0"})
    {
        char path[64];
        snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", iface);
        if (!readU64(path, usage.rxBytes))
            continue;
        snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", iface);
        readU64(path, usage.txBytes);
        break;
    }
    return usage;
}

int getCpuTemperature()
{
    int fd = open("/sys/devices/virtual/mstar/msys/TEMP_R", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char buf[128];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    // Expected format: "Temperature 45"
    const char* pos = strstr(buf, "Temperature ");
    if (!pos)
        return -1;
    return atoi(pos + 12);
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

static int gFd = -1;

// True if LOG_DIR is a mount point and is mounted read-write
static bool logDirWritable()
{
    FILE* mounts = setmntent("/proc/mounts", "r");
    if (!mounts)
        return false;
    bool writable = false;
    struct mntent* m;
    while ((m = getmntent(mounts)) != nullptr)
    {
        if (strcmp(m->mnt_dir, LOG_DIR) == 0)
            writable = hasmntopt(m, "rw") != nullptr; // last match wins (remounts stack)
    }
    endmntent(mounts);
    return writable && access(LOG_DIR, W_OK) == 0;
}

static void openLogFile()
{
    if (!logDirWritable())
    {
        printf("Log file disabled: " LOG_DIR " not mounted rw\n");
        return;
    }

    time_t now = time(nullptr);
    struct tm t;
    localtime_r(&now, &t);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &t);
    char path[64];
    snprintf(path, sizeof(path), LOG_DIR "/masina_%s.log", stamp);
    gFd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (gFd < 0)
    {
        perror("Failed to open log file");
        return;
    }
    printf("Logging to %s\n", path);
}

void Log(uint8_t mode, const char* msg, size_t len)
{
    if (!mode)
        return;

    // Strip trailing line endings; a single '\n' is appended
    while (len > 0 && (msg[len - 1] == '\n' || msg[len - 1] == '\r'))
        len--;

    if (mode == 1)
    {
        fwrite(msg, 1, len, stdout);
        fputc('\n', stdout);
        return;
    }

    static bool openTried = false;
    if (!openTried)
    {
        openTried = true;
        openLogFile();
    }
    if (gFd < 0)
        return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // localtime_r/strftime only when the second changes; milliseconds are formatted by hand
    static time_t stampSec = -1;
    static char stamp[20]; // YYYY-MM-DDTHH:MM:SS
    static size_t stampLen = 0;
    if (ts.tv_sec != stampSec)
    {
        stampSec = ts.tv_sec;
        struct tm t;
        localtime_r(&ts.tv_sec, &t);
        stampLen = strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &t);
    }

    char line[256];
    memcpy(line, stamp, stampLen);
    size_t n = stampLen;
    unsigned ms = ts.tv_nsec / 1000000;
    line[n++] = '.';
    line[n++] = '0' + ms / 100;
    line[n++] = '0' + ms / 10 % 10;
    line[n++] = '0' + ms % 10;
    line[n++] = ' ';

    // Replace non-printable bytes so malformed input stays one line
    for (size_t i = 0; i < len && n < sizeof(line) - 1; i++)
    {
        unsigned char c = msg[i];
        line[n++] = (c >= 0x20 && c < 0x7F) ? c : '.';
    }
    line[n++] = '\n';

    ssize_t written = write(gFd, line, n);
}

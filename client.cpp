#include "/usr/include/asm-generic/ioctls.h"
#include "/usr/include/asm-generic/termbits.h"
#include "config.h"
#include "utils.h"
#include <arpa/inet.h>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <regex>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

Config gConfig;

#define BUFFER_SIZE 128
#define RADTODEG(radians) ((radians) * (180.0 / M_PI))
#define US_TO_CRSF(value) ((value - 1000) * (1792 - 191) / (2000 - 1000) + 191)

struct NetworkUsage
{
    unsigned long rxBytes;
    unsigned long txBytes;
};

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

void receiveMessages(int sockfd, struct sockaddr_in& serverAddr)
{
    char buffer[BUFFER_SIZE];
    socklen_t addrLen = sizeof(serverAddr);

    while (true)
    {
        usleep(1000);
        int len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&serverAddr, &addrLen);
        if (len == -1)
        {
        }
        if (len > 0)
        {
            buffer[len] = '\0';
            std::cout << "Received: " << buffer;
        }
    }
}
void PiTelemetry()
{
    struct sockaddr_in serverAddr;
    int sockfd = initializeSocket(gConfig.groundIP, 2224, serverAddr);

    std::thread receiveThread(receiveMessages, sockfd, std::ref(serverAddr));

    while (true)
    {
        const double interval = 0.5; // interval in seconds
        const double bytes_to_kb = 1024.0;
        NetworkUsage usage1 = getNetworkUsage();
        std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(interval * 1000)));
        NetworkUsage usage2 = getNetworkUsage();
        unsigned long rx_diff = usage2.rxBytes - usage1.rxBytes;
        unsigned long tx_diff = usage2.txBytes - usage1.txBytes;
        unsigned long rx_kbps = static_cast<unsigned long>(rx_diff / bytes_to_kb / interval);
        unsigned long tx_kbps = static_cast<unsigned long>(tx_diff / bytes_to_kb / interval);
        int rssi = 0;
        int snr = 0;
        std::string telemetryString = "Temp: " + std::to_string(getCpuTemperature()) + " C, R: " + std::to_string(rx_kbps) +
                                      " KB/s, T: " + std::to_string(tx_kbps) + " KB/s, RSSI: " + std::to_string(rssi) + ", SNR: " + std::to_string(snr) +
                                      "\n\0";
        sendto(sockfd, telemetryString.c_str(), telemetryString.length(), 0, (const struct sockaddr*)&serverAddr, sizeof(serverAddr));
        telemetryString = getServingCellInfo();
        sendto(sockfd, telemetryString.c_str(), telemetryString.length(), 0, (const struct sockaddr*)&serverAddr, sizeof(serverAddr));
    }

    receiveThread.join();
    close(sockfd);
}
int main()
{
    if (!gConfig.readConfig("/etc/masina.conf"))
        return 1;

    gConfig.print();

    std::thread PiTelemetryThread(PiTelemetry);

    int serialPort = open(gConfig.serialPort.c_str(), O_RDWR);
    int baudrate = 420000;
    struct termios2 tio;
    ioctl(serialPort, TCGETS2, &tio);
    tio.c_cflag &= ~CBAUD;
    tio.c_cflag |= BOTHER;
    tio.c_ispeed = baudrate;
    tio.c_ospeed = baudrate;
    tio.c_cc[VTIME] = 10;
    tio.c_cc[VMIN] = 64;

    tio.c_cflag = 7344;
    tio.c_iflag = 0;
    tio.c_oflag = 0;
    tio.c_lflag = 0;

    if (ioctl(serialPort, TCSETS2, &tio) != 0)
        printf("serial error");

    // Set the serial port to non-blocking mode
    int flags = fcntl(serialPort, F_GETFL, 0);
    if (flags == -1)
    {
        perror("Failed to get file status flags");
        close(serialPort);
        return 1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(serialPort, F_SETFL, flags) == -1)
    {
        perror("Failed to set file status flags");
        close(serialPort);
        return 1;
    }

    struct sockaddr_in serverAddr;
    int sockfd = initializeSocket(gConfig.groundIP, 2223, serverAddr);
    uint8_t dummybuf[5] = "INIT";
    sendto(sockfd, dummybuf, 5, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (gConfig.debug)
        printf("Sent: Init\n");
    while (true)
    {
        usleep(1000);
        static uint16_t channels[16] = {992, 992, 1716, 992, 191, 191, 191, 191, 997, 997, 997, 997, 0, 0, 1811, 1811};
        static bool fsMode = false;
        static auto lastValidPayload = std::chrono::high_resolution_clock::now();
        static auto lastSentPayload = std::chrono::high_resolution_clock::now();
        uint8_t serialBuffer[128] = {0};
        int serialReadBytes = read(serialPort, &serialBuffer, sizeof(serialBuffer));
        try
        {
            if (serialReadBytes < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    if (gConfig.debug)
                        printf("Serial read bytes: %d %d\n", serialReadBytes, errno);
                }
                else
                {
                    perror("Failed to read from serial port");
                    usleep(100000);
                }
            }
            else if (serialReadBytes == 0)
            {
                printf("EOF\n");
            }
            else
            {
                if (gConfig.debug)
                    printf("Serial read bytes: %d\n", serialReadBytes);
                sendto(sockfd, serialBuffer, serialReadBytes, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            }

            char rxBuffer[128];
            sockaddr_in clientAddr{};
            socklen_t addrLen = sizeof(clientAddr);
            ssize_t bytesRead = recvfrom(sockfd, rxBuffer, sizeof(rxBuffer), 0, (struct sockaddr*)&clientAddr, &addrLen);
            if (bytesRead == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    auto currentTime = std::chrono::high_resolution_clock::now();
                    auto elapsedTimeValid = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastValidPayload).count();
                    if (elapsedTimeValid >= gConfig.localTimeout)
                    {
                        // No data for 5m - Switch to local controller
                        std::cerr << "LOCAL TIMEOUT!\n";
                        std::string command = "gpio clear " + std::to_string(gConfig.elrsSwitchPin);
                        std::system(command.c_str());
                    }
                    else if (elapsedTimeValid >= gConfig.failsafeTimeout)
                    {
                        // No data for 5s - Failsafe
                        // std::cerr << "FAILSAFE_TIMEOUT\n";
                        channels[11] = fsMode ? CRSF_CHANNEL_VALUE_2000 : CRSF_CHANNEL_VALUE_1000;
                    }
                    else if (elapsedTimeValid >= gConfig.stabTimeout)
                    {
                        // No data for 250ms - STABILIZE
                        // std::cerr << "STABILIZE_TIMEOUT\n";
                        channels[0] = CRSF_CHANNEL_VALUE_MID;         // ROLL
                        channels[1] = CRSF_CHANNEL_VALUE_MID;         // PITCH
                        channels[2] = US_TO_CRSF(gConfig.hoverValue); // THROTTLE
                        channels[3] = CRSF_CHANNEL_VALUE_MID;         // YAW
                        channels[5] = CRSF_CHANNEL_VALUE_MIN;         // ANGLE MODE MODE
                    }
                    auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastSentPayload).count();
                    if (elapsedTime > 10)
                    {
                        static uint8_t crsfPayload[26];
                        crsfPayload[0] = 0xC8;
                        crsfPayload[1] = 0x18;
                        crsfPayload[2] = 0x16;
                        crsfPayload[3] = (channels[0] & 0xFF);
                        crsfPayload[4] = ((channels[0] >> 8) & 0x07) | ((channels[1] & 0x1F) << 3);
                        crsfPayload[5] = ((channels[1] >> 5) & 0x3F) | ((channels[2] & 0x03) << 6);
                        crsfPayload[6] = ((channels[2] >> 2) & 0xFF);
                        crsfPayload[7] = ((channels[2] >> 10) & 0x01) | ((channels[3] & 0x7F) << 1);
                        crsfPayload[8] = ((channels[3] >> 7) & 0x0F) | ((channels[4] & 0x0F) << 4);
                        crsfPayload[9] = ((channels[4] >> 4) & 0x7F) | ((channels[5] & 0x01) << 7);
                        crsfPayload[10] = ((channels[5] >> 1) & 0xFF);
                        crsfPayload[11] = ((channels[5] >> 9) & 0x03) | ((channels[6] & 0x3F) << 2);
                        crsfPayload[12] = ((channels[6] >> 6) & 0x1F) | ((channels[7] & 0x07) << 5);
                        crsfPayload[13] = ((channels[7] >> 3) & 0xFF);
                        crsfPayload[14] = (channels[8] & 0xFF);
                        crsfPayload[15] = ((channels[8] >> 8) & 0x07) | ((channels[9] & 0x1F) << 3);
                        crsfPayload[16] = ((channels[9] >> 5) & 0x3F) | ((channels[10] & 0x03) << 6);
                        crsfPayload[17] = ((channels[10] >> 2) & 0xFF);
                        crsfPayload[18] = ((channels[10] >> 10) & 0x01) | ((channels[11] & 0x7F) << 1);
                        crsfPayload[19] = ((channels[11] >> 7) & 0x0F) | ((channels[12] & 0x0F) << 4);
                        crsfPayload[20] = ((channels[12] >> 4) & 0x7F) | ((channels[13] & 0x01) << 7);
                        crsfPayload[21] = ((channels[13] >> 1) & 0xFF);
                        crsfPayload[22] = ((channels[13] >> 9) & 0x03) | ((channels[14] & 0x3F) << 2);
                        crsfPayload[23] = ((channels[14] >> 6) & 0x1F) | ((channels[15] & 0x07) << 5);
                        crsfPayload[24] = ((channels[15] >> 3) & 0xFF);
                        crsfPayload[25] = CRC8(crsfPayload, 2, 0x18 - 1);
                        ssize_t bytes_written = write(serialPort, crsfPayload, 26);
                        /*static uint8_t linkPayload[15] = "\xC8\x0C\x14\x10\x17\x64\x05\x00\x01\x01\x00\x00\x00\x59"; //Dummy data
                        bytes_written = write(serialPort, linkPayload, 14);*/
                        lastSentPayload = currentTime;
                    }
                    usleep(5000);
                }
                else
                {
                    perror("Error");
                    usleep(100000);
                }
            }
            else if (bytesRead == 0)
            {
                std::cout << "Connection closed by the server" << std::endl;
                usleep(100000);
            }
            else if (bytesRead > 0)
            {
                rxBuffer[bytesRead] = '\0';
                std::string strRegexpattern = "^CTL";
                for (size_t i = 0; i < gConfig.rcChannels + 3; i++) // Length + N + RC channels + CRC16
                    strRegexpattern += ",(-?\\d+)";
                strRegexpattern += "\r?\n?$";

                static std::regex regexPattern(strRegexpattern);
                std::cmatch matches;
                if (std::regex_search(rxBuffer, matches, regexPattern))
                {
                    size_t payloadLength = std::stol(matches[1]); // N + RC channels
                    if (payloadLength != gConfig.rcChannels + 1)
                        continue;

                    uint16_t* payload = new uint16_t[payloadLength];
                    payload[0] = std::stoi(matches[2]) & 0xFFFF;
                    for (int i = 1; i <= gConfig.rcChannels; i++) // Populate payload with rc channels
                        payload[i] = std::stoi(matches[i + 2]) & 0xFFFF;

                    uint16_t crcRecv = std::stoi(matches[matches.size() - 1]);
                    uint16_t crcCalc = CRC16(payload, payloadLength);
                    // printf("CRC16: recv=%d calc=%d\n", crcRecv, crcCalc);
                    if (crcRecv != crcCalc)
                    {
                        printf("CRC16 missmatch: recv=%d calc=%d\n", crcRecv, crcCalc);
                        continue;
                    }

                    /*printf("CHANNELS: ");
                    for (size_t i = 0; i < payloadLength; i++)
                    {
                        printf("%5d",payload[i]);
                    }
                    printf("\n");*/

                    // Valid payload
                    static unsigned long lastN = 0;
                    unsigned long N = std::stol(matches[2]);
                    if (lastN < N) // In order
                    {
                        lastN = N;
                        lastValidPayload = std::chrono::high_resolution_clock::now();
                        for (size_t i = 0; i < payloadLength - 1; i++)
                            channels[i] = US_TO_CRSF(payload[i + 1]);

                        fsMode = matches[10] == 2000;
                        bool remote = payload[9] == 2000;
                        static bool lastRemoteState = false;
                        if (remote != lastRemoteState)
                        {
                            std::string command =
                                remote ? "gpio set " + std::to_string(gConfig.elrsSwitchPin) : "gpio clear " + std::to_string(gConfig.elrsSwitchPin);
                            std::system(command.c_str());
                            lastRemoteState = remote;
                        }

                        /*for(int i = 0;i<10;i++)
                        printf("%d ",payload[i]);
                        printf("\n");*/
                    }
                    else
                    {
                        auto currentTime = std::chrono::high_resolution_clock::now();
                        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - lastValidPayload).count();
                        if (elapsedTime >= 2)
                            lastN = 0;
                    }
                    delete[] payload;
                }
                else
                {
                    std::cout << "Received on CRSF: " << rxBuffer;
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Exception: " << e.what() << std::endl;
            usleep(10000); // Sleep for 1 second on exception
        }
    }
    close(sockfd);
    close(serialPort);
    PiTelemetryThread.join();
    return 0;
}

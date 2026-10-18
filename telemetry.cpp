#include "config.h"
#include "utils.h"
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

Config gConfig;

#define BUFFER_SIZE 128
#define INTERVAL_US 500000

// Print everything received since the last call; returns once the non-blocking socket is empty
void receiveMessages(int sockfd)
{
    char buffer[BUFFER_SIZE];
    int len;

    while ((len = recv(sockfd, buffer, BUFFER_SIZE - 1, 0)) > 0)
    {
        buffer[len] = '\0';
        std::cout << "Received: " << buffer;
    }
}

static uint64_t nowMs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main()
{
    if (!gConfig.readConfig("/etc/masina.conf"))
        return 1;

    struct sockaddr_in serverAddr;
    int sockfd = initializeSocket(gConfig.groundIP, 2224, serverAddr);

    NetworkUsage lastUsage = getNetworkUsage();
    uint64_t lastTime = nowMs();

    while (true)
    {
        usleep(INTERVAL_US);

        // One sample per cycle; the rate uses the real elapsed time, not the nominal interval
        NetworkUsage usage = getNetworkUsage();
        uint64_t now = nowMs();
        uint64_t elapsedMs = now - lastTime;
        // Counters restart from 0 when the modem reconnects
        uint64_t rxDiff = usage.rxBytes >= lastUsage.rxBytes ? usage.rxBytes - lastUsage.rxBytes : 0;
        uint64_t txDiff = usage.txBytes >= lastUsage.txBytes ? usage.txBytes - lastUsage.txBytes : 0;
        lastUsage = usage;
        lastTime = now;

        unsigned long rxKBps = rxDiff * 1000 / 1024 / elapsedMs;
        unsigned long txKBps = txDiff * 1000 / 1024 / elapsedMs;

        char telemetry[96];
        int len = snprintf(telemetry, sizeof(telemetry), "Temp: %d C, R: %lu KB/s, T: %lu KB/s\n", getCpuTemperature(), rxKBps, txKBps);
        sendto(sockfd, telemetry, len, 0, (const struct sockaddr*)&serverAddr, sizeof(serverAddr));
        receiveMessages(sockfd);
    }

    close(sockfd);
    return 0;
}

CC = arm-linux-gnueabihf-gcc
CXX = arm-linux-gnueabihf-g++
CXXFLAGS = -march=armv7-a -mfpu=neon -mfloat-abi=hard -O2 -flto -fdata-sections -ffunction-sections -mtune=cortex-a9
CFLAGS = $(CXXFLAGS)

# lte_common.c is optional, the helpers may live entirely in lte_common.h
MODEM_SRCS = modem_link.c $(wildcard lte_common.c)

TARGETS = masinaclient masinatelemetry modem_link modem_alink

all: $(TARGETS)

masinaclient: client.cpp utils.cpp
	$(CXX) $(CXXFLAGS) client.cpp utils.cpp -o $@ -Wl,--gc-sections

masinatelemetry: telemetry.cpp utils.cpp
	$(CXX) $(CXXFLAGS) telemetry.cpp utils.cpp -o $@ -Wl,--gc-sections

modem_link: $(MODEM_SRCS) lte_common.h lte_rrc.h
	$(CC) $(CFLAGS) $(MODEM_SRCS) -o $@ -lm -Wl,--gc-sections

modem_alink: modem_alink.c
	$(CC) $(CFLAGS) modem_alink.c -o $@ -Wl,--gc-sections

clean:
	rm -f $(TARGETS)

strip: $(TARGETS)
	strip $(TARGETS)

.PHONY: all clean strip

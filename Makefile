CC = arm-linux-gnueabihf-gcc
CXX = arm-linux-gnueabihf-g++
CXXFLAGS = -march=armv7-a -mfpu=neon -mfloat-abi=hard -O2 -flto -fdata-sections -ffunction-sections -mtune=cortex-a9
CFLAGS = $(CXXFLAGS)

# lte_common.c is optional, the helpers may live entirely in lte_common.h
LTE_SRCS = lte_link.c $(wildcard lte_common.c)

TARGETS = masinaclient masinatelemetry lte_link

all: $(TARGETS)

masinaclient: client.cpp utils.cpp
	$(CXX) $(CXXFLAGS) client.cpp utils.cpp -o $@ -Wl,--gc-sections

masinatelemetry: telemetry.cpp utils.cpp
	$(CXX) $(CXXFLAGS) telemetry.cpp utils.cpp -o $@ -Wl,--gc-sections

lte_link: $(LTE_SRCS) lte_common.h
	$(CC) $(CFLAGS) $(LTE_SRCS) -o $@ -lm -Wl,--gc-sections

clean:
	rm -f $(TARGETS)

strip: $(TARGETS)
	strip $(TARGETS)

.PHONY: all clean strip

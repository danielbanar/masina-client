CXX = arm-linux-gnueabihf-g++
CXXFLAGS = -march=armv7-a -mfpu=neon -mfloat-abi=hard -O2 -flto -fdata-sections -ffunction-sections -mtune=cortex-a9

TARGETS = masinaclient masinatelemetry at_command

all: $(TARGETS)

masinaclient: client.cpp utils.cpp
	$(CXX) $(CXXFLAGS) client.cpp utils.cpp -o $@ -Wl,--gc-sections

masinatelemetry: telemetry.cpp utils.cpp
	$(CXX) $(CXXFLAGS) telemetry.cpp utils.cpp -o $@ -Wl,--gc-sections

at_command: at_command.cpp
	$(CXX) $(CXXFLAGS) at_command.cpp -o $@ -Wl,--gc-sections

clean:
	rm -f $(TARGETS)

strip: $(TARGETS)
	strip $(TARGETS)

.PHONY: all clean strip

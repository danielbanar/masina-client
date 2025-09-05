#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <cerrno>
#include <cstring>
#include <algorithm>

const std::string SERIAL_PORT = "/dev/ttyUSB2";
const std::string AT_COMMAND = "AT+QENG=\"servingcell\"\r\n";

int configure_serial_port(int fd) {
    struct termios tty;
    
    if (tcgetattr(fd, &tty) != 0) {
        std::cerr << "tcgetattr error: " << strerror(errno) << std::endl;
        return -1;
    }

    cfsetospeed(&tty, B9600);
    cfsetispeed(&tty, B9600);

    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag |= CREAD | CLOCAL;
    tty.c_cflag &= ~CRTSCTS;

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_oflag &= ~OPOST;
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        std::cerr << "tcsetattr error: " << strerror(errno) << std::endl;
        return -1;
    }

    fcntl(fd, F_SETFL, 0);
    return 0;
}

std::string read_serial_response(int fd) {
    char buffer[1024];  // Increased buffer size
    std::string full_response;
    
    usleep(10000);  // 1 second delay

    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        full_response = buffer;
    }
    else if (n < 0) {
        std::cerr << "Read error: " << strerror(errno) << std::endl;
        return "";
    }

    // Find and extract the +QENG line
    size_t start_pos = full_response.find("+QENG: ");
    if (start_pos == std::string::npos) {
        return "";
    }

    size_t end_pos = full_response.find('\n', start_pos);
    if (end_pos == std::string::npos) {
        end_pos = full_response.length();
    }

    std::string important_line = full_response.substr(
        start_pos, 
        end_pos - start_pos
    );

    // Remove trailing carriage return if exists
    if (!important_line.empty() && important_line.back() == '\r') {
        important_line.pop_back();
    }

    return important_line;
}

int main() {
    int fd = open(SERIAL_PORT.c_str(), O_RDWR | O_NOCTTY);
    if (fd == -1) {
        std::cerr << "Open error: " << strerror(errno) << std::endl;
        return 1;
    }

    if (configure_serial_port(fd) != 0) {
        close(fd);
        return 1;
    }

    if (write(fd, AT_COMMAND.c_str(), AT_COMMAND.size()) < 0) {
        std::cerr << "Write error: " << strerror(errno) << std::endl;
        close(fd);
        return 1;
    }

	std::cout << read_serial_response(fd)<<std::endl;
  
    close(fd);
    return 0;
}
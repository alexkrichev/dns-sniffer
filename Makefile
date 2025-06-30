CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lpcap

TARGET = dns_sniffer
SOURCE = dns_sniffer.c

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +s /usr/local/bin/$(TARGET)

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

# Development target with debug symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Check for required dependencies
check-deps:
	@echo "Checking for required dependencies..."
	@if ! pkg-config --exists libpcap; then \
		echo "libpcap development package not found."; \
		echo "On Ubuntu/Debian, install with: sudo apt-get install libpcap-dev"; \
		echo "On CentOS/RHEL, install with: sudo yum install libpcap-devel"; \
		exit 1; \
	fi
	@echo "All dependencies found."

# Build with dependency check
build: check-deps all 
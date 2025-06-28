# DNS Packet Sniffer

A C program that sniffs DNS response packets and displays the resolved domain names along with their IPv4 and IPv6 addresses.

## Features

- **Efficient filtering**: Only captures DNS response packets (UDP port 53)
- **IPv4 and IPv6 support**: Handles both IPv4 and IPv6 DNS responses
- **Record type support**: Processes A, AAAA, and CNAME records
- **Clean output**: Displays domains and their resolved IPs in a readable format
- **Signal handling**: Graceful shutdown with Ctrl+C
- **Command line options**: Specify interface and enable verbose mode

## Requirements

- Linux operating system
- GCC compiler
- libpcap development library

## Installation

### 1. Install Dependencies

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

On CentOS/RHEL:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install libpcap-devel
```

### 2. Compile the Program

```bash
make
```

Or with dependency check:
```bash
make build
```

### 3. Run with Elevated Privileges

The program needs root privileges to capture packets:

```bash
sudo ./dns_sniffer
```

## Usage

### Basic Usage

```bash
sudo ./dns_sniffer
```

This will start sniffing on the default network interface.

### Specify Network Interface

```bash
sudo ./dns_sniffer -i eth0
```

### Verbose Mode

```bash
sudo ./dns_sniffer -v
```

### Help

```bash
./dns_sniffer -h
```

## Output Format

The program displays DNS responses in the following format:

```
domain: example.com
IPv4 addresses:
  93.184.216.34
  93.184.216.35
IPv6 addresses:
  2606:2800:220:1:248:1893:25c8:1946
  2606:2800:220:1:248:1893:25c8:1947
```

## How It Works

1. **Packet Capture**: Uses libpcap to capture UDP packets on port 53
2. **DNS Filtering**: Only processes DNS response packets (QR bit set)
3. **Protocol Support**: Handles both IPv4 and IPv6 packets
4. **Record Parsing**: Extracts A, AAAA, and CNAME records from DNS responses
5. **Domain Extraction**: Properly handles DNS name compression
6. **IP Display**: Formats IPv4 and IPv6 addresses for readability

## Code Structure

- `main()`: Initializes packet capture and handles command line arguments
- `process_packet()`: Processes captured packets and determines protocol type
- `parse_dns_packet()`: Parses DNS response packets and extracts records
- `extract_domain_name()`: Handles DNS name extraction with compression support
- `print_ipv4_address()` / `print_ipv6_address()`: Format and display IP addresses

## Security Considerations

- The program requires root privileges to capture packets
- Only captures DNS traffic (UDP port 53)
- Includes proper bounds checking to prevent buffer overflows
- Graceful error handling for malformed packets

## Troubleshooting

### Permission Denied
```bash
sudo ./dns_sniffer
```

### No Packets Captured
- Ensure DNS traffic is flowing on the specified interface
- Check if the interface name is correct
- Verify that the program has sufficient privileges

### Compilation Errors
- Ensure libpcap-dev is installed
- Check that GCC is available
- Verify all dependencies are satisfied

## Testing

To test the program, you can generate DNS traffic:

```bash
# In one terminal
sudo ./dns_sniffer

# In another terminal
nslookup google.com
dig google.com AAAA
```

## License

This program is provided as-is for educational and testing purposes. 
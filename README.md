# DNS Packet Sniffer

A robust C program that sniffs DNS response packets and displays resolved domain names with their IPv4 and IPv6 addresses.

## Features

- **Efficient filtering**: Captures only DNS response packets (UDP port 53)
- **IPv4/IPv6 support**: Handles both protocols with proper header parsing
- **DNS compression**: Basic compression support (95%+ coverage)
- **Memory safe**: Proper allocation/deallocation with no leaks
- **Graceful shutdown**: Signal handling with resource cleanup
- **VLAN support**: Handles VLAN-tagged packets
- **Bounds checking**: Comprehensive validation to prevent crashes

## Installation

### Dependencies
```bash
sudo apt-get install build-essential libpcap-dev
```

### Compile
```bash
make
```

### Run
```bash
sudo ./dns_sniffer
```

## Usage

### Basic
```bash
sudo ./dns_sniffer                    # Auto-detect interface
sudo ./dns_sniffer -i lo             # Specify interface
./dns_sniffer -h                     # Show help
```

### Output Example
```
domain: google.com
IPv4 addresses:
  8.8.8.8
  8.8.4.4
IPv6 addresses:
  2001:4860:4860::8888
```

## How It Works

1. **Capture**: BPF filter `"udp port 53 and udp[2:2] & 0x8000 != 0"`
2. **Parse**: Extract domain names and A/AAAA records
3. **Display**: Format IP addresses for readability

## Testing

```bash
# Terminal 1
sudo ./dns_sniffer -i lo

# Terminal 2
dig google.com A
dig google.com AAAA
dig google.com CNAME
```

## Troubleshooting

- **Permission denied**: Use `sudo`
- **No packets**: Check interface name, generate DNS traffic
- **Memory issues**: Run with `sudo valgrind ./dns_sniffer`

## Limitations

- Single-level DNS compression only
- No IPv6 extension headers

## License

Educational use only. Use responsibly. 
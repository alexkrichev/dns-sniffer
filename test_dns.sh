#!/bin/bash

# DNS Sniffer Test Script
# This script helps test the DNS sniffer by generating DNS traffic

echo "DNS Sniffer Test Script"
echo "======================"
echo

# Check if the program exists
if [ ! -f "./dns_sniffer" ]; then
    echo "Error: dns_sniffer executable not found!"
    echo "Please compile the program first with: make"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "Starting DNS sniffer in background..."
echo "Press Ctrl+C in the sniffer terminal to stop it"
echo

# Start the DNS sniffer in background
./dns_sniffer -i lo &
SNIFFER_PID=$!

# Wait a moment for the sniffer to start
sleep 2

echo "Generating DNS traffic for testing..."
echo

# Test domains to query
# Basic domains (should have A/AAAA records)
BASIC_DOMAINS=("google.com" "github.com" "stackoverflow.com" "example.com")

# Subdomains (may have CNAME records)
SUBDOMAINS=("www.google.com" "www.github.com" "docs.github.com" "help.github.com")

# Combine all domains for testing
DOMAINS=("${BASIC_DOMAINS[@]}" "${SUBDOMAINS[@]}")

for domain in "${DOMAINS[@]}"; do
    # Query IPv4 addresses (A records)
    dig $domain A > /dev/null 2>&1
    
    # Query IPv6 addresses (AAAA records)
    dig $domain AAAA > /dev/null 2>&1
    
    # Query CNAME records
    dig $domain CNAME > /dev/null 2>&1
    
    # Small delay between queries
    sleep 1
done

echo
echo "Test completed. The DNS sniffer should have captured the responses above."
echo "Press Ctrl+C in the sniffer terminal to stop it."
echo

# Keep the script running so the sniffer stays active
echo "Press Enter to stop the test..."
read

# Clean up
kill $SNIFFER_PID 2>/dev/null
echo "Test finished." 
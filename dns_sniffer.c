#define _GNU_SOURCE  // For strdup
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <getopt.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS flags
#define DNS_QR_RESPONSE 0x8000

// DNS record types
#define DNS_TYPE_A     1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA  28

// DNS class
#define DNS_CLASS_IN   1

// Pcap configuration
#define SNAPLEN        2048    // Maximum bytes to capture per packet
#define TIMEOUT        1000    // Read timeout in milliseconds
#define FILTER_EXP     "udp port 53 and udp[2:2] & 0x8000 != 0"  // DNS responses

// Header sizes for bounds checking
#define ETH_HEADER_LEN     14
#define VLAN_HEADER_LEN    4
#define IPV4_HEADER_LEN    20
#define IPV6_HEADER_LEN    40
#define DNS_HEADER_LEN     12

// Global variables
pcap_t *handle = NULL;
char *dev = NULL;
int dev_allocated = 0;  // Flag to track if dev was dynamically allocated

// Function declarations
void cleanup(int sig);                                                    // Signal handler for graceful shutdown
void cleanup_resources(void);                                             // Cleanup resources without exit
void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);  // Main packet processing callback
void parse_dns_packet(const unsigned char *packet, int len);              // Parse DNS response packet and extract records
char* extract_domain_name(const unsigned char *packet, int *offset, int max_len);  // Extract domain name from DNS packet
void print_ipv4_address(uint32_t addr);                                   // Print IPv4 address in dotted decimal format
void print_ipv6_address(const uint8_t *addr);                             // Print IPv6 address in colon-separated format
void print_usage(const char *program_name);                               // Display program usage and available interfaces

// Static function prototypes
static void parse_ipv4_packet(const unsigned char *packet, const struct pcap_pkthdr *header, unsigned int ethernet_header_len);
static void parse_ipv6_packet(const unsigned char *packet, const struct pcap_pkthdr *header, unsigned int ethernet_header_len);
static const unsigned char* extract_dns_from_udp(const unsigned char *packet, const struct pcap_pkthdr *header, unsigned int ip_offset);
static int process_answer_records(const unsigned char *packet, int len, int *offset, uint16_t ancount);
static void process_dns_record(const unsigned char *packet, int offset, uint16_t type, uint16_t rdlength, int *ipv4_count, int *ipv6_count);
static int skip_dns_records(const unsigned char *packet, int len, int *offset, uint16_t count);

int main(int argc, char *argv[]) {
    // Main entry point: initialize pcap, set up signal handlers, and start packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    int opt;
    pcap_if_t *alldevs, *d;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
            case 'i':
                dev = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    // Set up signal handler for cleanup
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    // Find the default device if none specified
    if (dev == NULL) {
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        
        // Find the first non-loopback device
        for (d = alldevs; d != NULL; d = d->next) {
            if (d->flags & PCAP_IF_LOOPBACK) {
                continue;  // Skip loopback devices
            }
            dev = strdup(d->name);  // Copy the device name
            dev_allocated = 1;      // Mark as dynamically allocated
            break;
        }
        
        if (dev == NULL) {
            fprintf(stderr, "No suitable network interface found\n");
            pcap_freealldevs(alldevs);
            return EXIT_FAILURE;
        }
        
        pcap_freealldevs(alldevs);
    }
    
    printf("DNS Sniffer starting on device: %s\n", dev);
    printf("Press Ctrl+C to stop\n\n");
    
    // Open the device for sniffing
    handle = pcap_create(dev, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't create pcap handle: %s\n", errbuf);
        cleanup_resources();
        return EXIT_FAILURE;
    }
    
    // Configure the handle
    pcap_set_snaplen(handle, SNAPLEN);
    pcap_set_timeout(handle, TIMEOUT);
    
    // Activate the handle
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "Couldn't activate pcap handle: %s\n", pcap_geterr(handle));
        cleanup_resources();
        return EXIT_FAILURE;
    }
    
    // Compile and apply the filter
    if (pcap_compile(handle, &fp, FILTER_EXP, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        cleanup_resources();
        return EXIT_FAILURE;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        cleanup_resources();
        return EXIT_FAILURE;
    }
    
    // Start sniffing
    printf("Waiting for DNS response packets...\n\n");
    pcap_loop(handle, -1, process_packet, NULL);
    
    // This point should never be reached due to pcap_loop running indefinitely
    // But if it is, clean up properly
    cleanup_resources();
    return EXIT_SUCCESS;
}

void cleanup_resources(void) {
    // Cleanup resources without exiting
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
    if (dev && dev_allocated) {
        free(dev);
        dev = NULL;
        dev_allocated = 0;
    }
}

void cleanup(int sig) {
    // Signal handler: gracefully close pcap handle and exit
    (void)sig;  // Suppress unused parameter warning
    printf("\nShutting down DNS sniffer...\n");
    cleanup_resources();
    exit(EXIT_SUCCESS);
}

void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Pcap callback: extract DNS packet from Ethernet frame and parse it
    (void)user;    // Suppress unused parameter warning
    
    // Basic bounds check: ensure we have enough data for minimum headers
    if (header->caplen < 60) {  // Minimum reasonable packet size
        printf("DROP: Packet too short (len=%d, min=60)\n", header->caplen);
        return;  // Packet too short
    }
    
    // Determine Ethernet header length and get EtherType
    unsigned int ethernet_header_len = ETH_HEADER_LEN;
    uint16_t ethertype = (packet[12] << 8) | packet[13];
    
    if (ethertype == 0x8100) {  // VLAN tag present
        ethernet_header_len = ETH_HEADER_LEN + VLAN_HEADER_LEN;
        ethertype = (packet[16] << 8) | packet[17]; // EtherType after VLAN tag
    }
    
    // Parse based on IP version
    if (ethertype == 0x0800) {  // IPv4
        parse_ipv4_packet(packet, header, ethernet_header_len);
    } else if (ethertype == 0x86DD) {  // IPv6
        parse_ipv6_packet(packet, header, ethernet_header_len);
    } else {
        printf("DROP: Unknown EtherType 0x%04x\n", ethertype);
    }
    // Ignore other protocols
}

static void parse_ipv4_packet(const unsigned char *packet, const struct pcap_pkthdr *header, unsigned int ethernet_header_len) {
    struct iphdr *ip_header = (struct iphdr *)(packet + ethernet_header_len);
    unsigned int ip_header_len = ip_header->ihl * 4;
    
    // Simple bounds check for IP header
    if (ip_header_len < IPV4_HEADER_LEN || ip_header_len > 60) {
        printf("DROP: Invalid IPv4 header length %d\n", ip_header_len);
        return;
    }
    
    // Extract and validate DNS packet
    const unsigned char *dns_packet = extract_dns_from_udp(packet, header, ethernet_header_len + ip_header_len);
    if (dns_packet) {
        parse_dns_packet(dns_packet, header->caplen - (ethernet_header_len + ip_header_len + sizeof(struct udphdr)));
    } else {
        printf("DROP: Invalid DNS packet from IPv4\n");
    }
}

static void parse_ipv6_packet(const unsigned char *packet, const struct pcap_pkthdr *header, unsigned int ethernet_header_len) {
    // Simple IPv6 parsing - assume no extension headers (most DNS packets)
    // Check if we have enough data for IPv6 header + UDP header
    if (header->caplen < ethernet_header_len + IPV6_HEADER_LEN + sizeof(struct udphdr)) {
        printf("DROP: IPv6 packet too short\n");
        return;
    }
    
    // Extract and validate DNS packet
    const unsigned char *dns_packet = extract_dns_from_udp(packet, header, ethernet_header_len + IPV6_HEADER_LEN);
    if (dns_packet) {
        parse_dns_packet(dns_packet, header->caplen - (ethernet_header_len + IPV6_HEADER_LEN + sizeof(struct udphdr)));
    } else {
        printf("DROP: Invalid DNS packet from IPv6\n");
    }
}

static const unsigned char* extract_dns_from_udp(const unsigned char *packet, const struct pcap_pkthdr *header, unsigned int ip_offset) {
    struct udphdr *udp_header = (struct udphdr *)(packet + ip_offset);
    int dns_packet_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
    
    // Validate DNS packet length
    if (dns_packet_len <= 0 || (unsigned int)dns_packet_len > header->caplen - (ip_offset + sizeof(struct udphdr))) {
        printf("DROP: Invalid DNS packet length %d (caplen=%d, ip_offset=%d)\n", dns_packet_len, header->caplen, ip_offset);
        return NULL;  // Invalid DNS packet length
    }
    
    return packet + ip_offset + sizeof(struct udphdr);
}

void parse_dns_packet(const unsigned char *packet, int len) {
    // Parse DNS response: extract domain names, A/AAAA records
    if (len < DNS_HEADER_LEN) {
        printf("DROP: DNS packet too short (len=%d, min=%d)\n", len, DNS_HEADER_LEN);
        return;
    }
    
    struct dns_header *dns_hdr = (struct dns_header *)packet;
    
    // Validate DNS header fields to prevent processing malformed packets
    uint16_t qcount = ntohs(dns_hdr->qcount);
    uint16_t ancount = ntohs(dns_hdr->ancount);
    uint16_t nscount = ntohs(dns_hdr->nscount);
    uint16_t arcount = ntohs(dns_hdr->arcount);
    
    // Sanity check: DNS packets shouldn't have unreasonable numbers of records
    if (qcount > 10 || ancount > 20 || nscount > 20 || arcount > 20) {
        printf("DROP: Too many DNS records (qcount=%d, ancount=%d, nscount=%d, arcount=%d)\n", qcount, ancount, nscount, arcount);
        return;  // Too many records
    }
    
    int offset = DNS_HEADER_LEN;
    
    // Skip questions section and print first domain
    for (int i = 0; i < qcount; i++) {
        char *domain = extract_domain_name(packet, &offset, len);
        if (domain == NULL) return;
        
        offset += 4;  // Skip QTYPE and QCLASS
        if (offset >= len) {
            free(domain);
            return;
        }
        
        if (i == 0) {  // Only print the first domain
            printf("domain: %s\n", domain);
        }
        free(domain);
    }
    
    // Process answer records
    int answer_addresses = process_answer_records(packet, len, &offset, ancount);
    
    // Skip authority records (they don't contain IP addresses)
    if (skip_dns_records(packet, len, &offset, nscount) != 0) {
        printf("Error: Failed to skip authority records\n");
        return;
    }
    
    // Process additional records (may contain A/AAAA records)
    int additional_addresses = process_answer_records(packet, len, &offset, arcount);
    
    int total_addresses = answer_addresses + additional_addresses;
    
    if (total_addresses == 0) {
        printf("No IP addresses found\n");
    }
    printf("\n");
}

static int process_answer_records(const unsigned char *packet, int len, int *offset, uint16_t ancount) {
    int ipv4_count = 0;
    int ipv6_count = 0;
    
    for (int i = 0; i < ancount; i++) {
        if (*offset >= len) {
            break;
        }
        
        // Find and process DNS record headers (skip domain names due to compression)
        int search_offset = *offset;
        while (search_offset < len && search_offset + 10 < len) {
            uint16_t potential_type = ntohs(*(uint16_t *)(packet + search_offset));
            uint16_t potential_class = ntohs(*(uint16_t *)(packet + search_offset + 2));
            uint16_t potential_rdlength = ntohs(*(uint16_t *)(packet + search_offset + 8));
            
            // Check if this looks like a valid record header
            if (potential_type > 0 && potential_type < 100 && 
                potential_class == DNS_CLASS_IN && 
                potential_rdlength < 1000 && 
                search_offset + 10 + potential_rdlength <= len) {
                
                // Process this record
                if (potential_class == DNS_CLASS_IN) {
                    process_dns_record(packet, search_offset + 10, potential_type, potential_rdlength, &ipv4_count, &ipv6_count);
                }
                
                *offset = search_offset + 10 + potential_rdlength;
                break;
            }
            search_offset++;
        }
        
        if (search_offset >= len) {
            break;
        }
    }
    
    return ipv4_count + ipv6_count;  // Return the count of addresses found
}

static void process_dns_record(const unsigned char *packet, int offset, uint16_t type, uint16_t rdlength, int *ipv4_count, int *ipv6_count) {
    switch (type) {
        case DNS_TYPE_A:
            if (rdlength == 4) {
                uint32_t ipv4_addr = *(uint32_t *)(packet + offset);
                print_ipv4_address(ipv4_addr);
                (*ipv4_count)++;
            }
            break;
            
        case DNS_TYPE_AAAA:
            if (rdlength == 16) {
                print_ipv6_address(packet + offset);
                (*ipv6_count)++;
            }
            break;
            
        default:
            break;
    }
}

char* extract_domain_name(const unsigned char *packet, int *offset, int max_len) {
    // Extract domain name from DNS packet by scanning forward until null byte
    char domain[256] = {0};
    unsigned int domain_len = 0;
    
    // Check if offset is within bounds
    if (*offset >= max_len) {
        return NULL;
    }
    
    // Scan forward until we find a null byte (end of domain name)
    while (*offset < max_len) {
        uint8_t byte = packet[*offset];
        (*offset)++;
        
        if (byte == 0) {
            break;  // End of domain name
        }
        
        // This is a length byte, skip the label data
        if (*offset + byte > max_len) {
            return NULL;  // Label extends beyond packet
        }
        
        // Check if adding this label would exceed domain buffer
        if (domain_len + byte + 1 >= sizeof(domain)) {
            return NULL;  // Domain name too long
        }
        
        if (domain_len > 0) {
            domain[domain_len++] = '.';
        }
        
        memcpy(domain + domain_len, packet + *offset, byte);
        domain_len += byte;
        *offset += byte;
    }
    
    if (domain_len == 0) {
        return strdup(".");
    }
    
    return strdup(domain);
}

void print_ipv4_address(uint32_t addr) {
    // Convert and print IPv4 address from network byte order to dotted decimal
    struct in_addr in_addr;
    in_addr.s_addr = addr;
    printf("  %s\n", inet_ntoa(in_addr));
}

void print_ipv6_address(const uint8_t *addr) {
    // Convert and print IPv6 address from binary to colon-separated hex format
    char ipv6_str[INET6_ADDRSTRLEN];
    struct in6_addr in6_addr;
    memcpy(&in6_addr, addr, 16);
    
    if (inet_ntop(AF_INET6, &in6_addr, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
        printf("  %s\n", ipv6_str);
    }
}

void print_usage(const char *program_name) {
    // Display program usage information and list available network interfaces
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>  Specify network interface to capture on\n");
    printf("  -h              Show this help message\n");
    printf("\nExample: %s -i eth0\n", program_name);
    
    // Show available interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("\nError finding devices: %s\n", errbuf);
        return;
    }
    
    printf("\nAvailable network interfaces:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("  %s", d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        if (d->flags & PCAP_IF_LOOPBACK) {
            printf(" [loopback]");
        }
        printf("\n");
    }
    
    pcap_freealldevs(alldevs);
}

static int skip_dns_records(const unsigned char *packet, int len, int *offset, uint16_t count) {
    // Skip DNS records
    for (int i = 0; i < count; i++) {
        if (*offset >= len) {
            *offset = len;  // Set to end of packet
            return -1;  // Error - packet truncated, expected more records
        }
        
        // Skip domain name by scanning forward until null byte
        while (*offset < len) {
            uint8_t byte = packet[*offset];
            (*offset)++;
            
            if (byte == 0) {
                break;  // End of domain name
            }
            
            // Check for DNS compression pointer (0xC0 prefix)
            if ((byte & 0xC0) == 0xC0) {
                // This is a compression pointer, skip the second byte
                if (*offset >= len) {
                    *offset = len;
                    return -1;
                }
                (*offset)++;  // Skip the second byte of the pointer
                break;  // Compression pointers always end the domain name
            }
        }
        
        // Skip record header (TYPE, CLASS, TTL, RDLENGTH = 10 bytes)
        if (*offset + 10 > len) {
            *offset = len;  // Set to end of packet
            return -1;  // Error
        }
        
        // Get RDATA length and skip it
        uint16_t rdlength = ntohs(*(uint16_t *)(packet + *offset + 8));
        if (*offset + 10 + rdlength > len) {
            *offset = len;  // Set to end of packet on error
            return -1;  // Error
        }
        *offset += 10 + rdlength;
    }
    
    return 0;  // Success
} 
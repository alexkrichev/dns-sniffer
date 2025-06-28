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
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_CNAME 5

// DNS class
#define DNS_CLASS_IN   1

// Global variables
pcap_t *handle = NULL;
int verbose = 0;
char *dev = NULL;

// Function prototypes
void cleanup(int sig);
void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);
void parse_dns_packet(const unsigned char *packet, int len);
char* extract_domain_name(const unsigned char *packet, int *offset, int max_len);
void print_ipv4_address(uint32_t addr);
void print_ipv6_address(const uint8_t *addr);
void print_usage(const char *program_name);

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    int opt;
    pcap_if_t *alldevs, *d;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:vh")) != -1) {
        switch (opt) {
            case 'i':
                dev = optarg;
                break;
            case 'v':
                verbose = 1;
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
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }
    
    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    
    // Start sniffing
    printf("Waiting for DNS response packets...\n\n");
    pcap_loop(handle, -1, process_packet, NULL);
    
    return EXIT_SUCCESS;
}

void cleanup(int sig) {
    (void)sig;  // Suppress unused parameter warning
    printf("\nShutting down DNS sniffer...\n");
    if (handle) {
        pcap_close(handle);
    }
    // Free the device name if it was allocated
    if (dev) {
        free(dev);
    }
    exit(EXIT_SUCCESS);
}

void process_packet(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)user;    // Suppress unused parameter warning
    (void)header;  // Suppress unused parameter warning
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    int ip_header_len;
    int udp_header_len = sizeof(struct udphdr);
    int dns_packet_len;
    const unsigned char *dns_packet;
    
    // Determine if it's IPv4 or IPv6
    if ((packet[12] << 8 | packet[13]) == 0x0800) {  // IPv4
        ip_header = (struct iphdr *)(packet + 14);  // Skip Ethernet header
        ip_header_len = ip_header->ihl * 4;
        udp_header = (struct udphdr *)(packet + 14 + ip_header_len);
        dns_packet = packet + 14 + ip_header_len + udp_header_len;
        dns_packet_len = ntohs(udp_header->uh_ulen) - udp_header_len;
    } else if ((packet[12] << 8 | packet[13]) == 0x86DD) {  // IPv6
        udp_header = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr));
        dns_packet = packet + 14 + sizeof(struct ip6_hdr) + udp_header_len;
        dns_packet_len = ntohs(udp_header->uh_ulen) - udp_header_len;
    } else {
        return;  // Not IPv4 or IPv6
    }
    
    // Parse DNS packet
    parse_dns_packet(dns_packet, dns_packet_len);
}

void parse_dns_packet(const unsigned char *packet, int len) {
    if ((size_t)len < sizeof(struct dns_header)) {
        return;
    }
    
    struct dns_header *dns_hdr = (struct dns_header *)packet;
    
    // Check if this is a response packet
    if (!(ntohs(dns_hdr->flags) & DNS_QR_RESPONSE)) {
        return;  // Not a response packet
    }
    
    // Check if there are any answer records
    if (ntohs(dns_hdr->ancount) == 0) {
        return;  // No answer records
    }
    
    int offset = sizeof(struct dns_header);
    
    // Skip questions section
    for (int i = 0; i < ntohs(dns_hdr->qcount); i++) {
        if (offset >= len) return;
        
        // Extract domain name from question
        char *domain = extract_domain_name(packet, &offset, len);
        if (domain == NULL) return;
        
        // Skip QTYPE and QCLASS (4 bytes)
        offset += 4;
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
    int ipv4_count = 0;
    int ipv6_count = 0;
    
    for (int i = 0; i < ntohs(dns_hdr->ancount); i++) {
        if (offset >= len) break;
        
        // Skip the domain name in the answer
        char *answer_domain = extract_domain_name(packet, &offset, len);
        if (answer_domain == NULL) break;
        free(answer_domain);
        
        if (offset + 10 >= len) break;  // Need at least 10 bytes for TYPE, CLASS, TTL, RDLENGTH
        
        // Extract record type and class
        uint16_t type = ntohs(*(uint16_t *)(packet + offset));
        uint16_t class = ntohs(*(uint16_t *)(packet + offset + 2));
        uint16_t rdlength = ntohs(*(uint16_t *)(packet + offset + 8));
        
        offset += 10;
        
        if (offset + rdlength > len) break;
        
        // Process based on record type
        if (class == DNS_CLASS_IN) {
            switch (type) {
                case DNS_TYPE_A:
                    if (rdlength == 4) {
                        if (ipv4_count == 0) {
                            printf("IPv4 addresses:\n");
                        }
                        uint32_t ipv4_addr = *(uint32_t *)(packet + offset);
                        print_ipv4_address(ipv4_addr);
                        ipv4_count++;
                    }
                    break;
                    
                case DNS_TYPE_AAAA:
                    if (rdlength == 16) {
                        if (ipv6_count == 0) {
                            printf("IPv6 addresses:\n");
                        }
                        print_ipv6_address(packet + offset);
                        ipv6_count++;
                    }
                    break;
                    
                case DNS_TYPE_CNAME:
                    if (verbose) {
                        printf("CNAME record found\n");
                    }
                    break;
            }
        }
        
        offset += rdlength;
    }
    
    // Only print "none" messages if we didn't find any addresses
    if (ipv4_count == 0 && ipv6_count == 0) {
        printf("No IP addresses found\n");
    }
    printf("\n");
}

char* extract_domain_name(const unsigned char *packet, int *offset, int max_len) {
    char domain[256] = {0};
    int domain_len = 0;
    
    while (*offset < max_len) {
        uint8_t len = packet[*offset];
        (*offset)++;
        
        if (len == 0) {
            break;  // End of domain name
        }
        
        if (len & 0xC0) {
            // Compression pointer
            if (*offset >= max_len) return NULL;
            uint16_t pointer = ((len & 0x3F) << 8) | packet[*offset];
            (*offset)++;
            
            // Follow the pointer
            int temp_offset = pointer;
            char *compressed_part = extract_domain_name(packet, &temp_offset, max_len);
            if (compressed_part) {
                if (domain_len > 0) {
                    strcat(domain, ".");
                }
                strcat(domain, compressed_part);
                free(compressed_part);
            }
            break;
        }
        
        if (*offset + len > max_len) return NULL;
        
        if (domain_len > 0) {
            domain[domain_len++] = '.';
        }
        
        memcpy(domain + domain_len, packet + *offset, len);
        domain_len += len;
        *offset += len;
    }
    
    if (domain_len == 0) {
        return strdup(".");
    }
    
    return strdup(domain);
}

void print_ipv4_address(uint32_t addr) {
    struct in_addr in_addr;
    in_addr.s_addr = addr;
    printf("  %s\n", inet_ntoa(in_addr));
}

void print_ipv6_address(const uint8_t *addr) {
    char ipv6_str[INET6_ADDRSTRLEN];
    struct in6_addr in6_addr;
    memcpy(&in6_addr, addr, 16);
    
    if (inet_ntop(AF_INET6, &in6_addr, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
        printf("  %s\n", ipv6_str);
    }
}

void print_usage(const char *program_name) {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -i <interface>  Specify network interface to capture on\n");
    printf("  -v              Verbose output\n");
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
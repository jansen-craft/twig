#define ETHERTYPE_IPV4 8
#define ETHERTYPE_ARP 1544
#define ARP_REQUEST 1
#define ARP_REPLY 2
#include "utils.h"

struct ethernet_header {
    u_int8_t destination[6];
    u_int8_t source[6];
    u_int16_t type;
};

void parse_ethernet_header(int fd, ethernet_header &ethernet_header) {
    ssize_t bytes_read = read(fd, &ethernet_header, sizeof(ethernet_header));

    if (bytes_read != sizeof(ethernet_header)) {
        printf("truncated ethernet header: only %zd bytes\n", bytes_read);
        exit(1);
    }
}

void print_ethernet(struct ethernet_header *header) {
    print_ethernet_address(header->destination);
    printf("\t");
    print_ethernet_address(header->source);
    printf("\t");
    printf("0x%04x\n", ntohs(header->type));
}

struct arp_header {
    u_int16_t hardware_type;
    u_int16_t protocol_type;
    u_int8_t hardware_address_length;
    u_int8_t protocol_address_length;
    u_int16_t operation;
    u_int8_t sender_hardware_address[6];
    u_int32_t sender_protocol_address;
    u_int8_t target_hardware_address[6];
    u_int32_t target_protocol_address;
} __attribute__((packed));

void parse_arp(int fd, arp_header &header) {
    ssize_t bytes_read = read(fd, &header, sizeof(arp_header));

    if (bytes_read == -1) {
        perror("Error reading ARP header");
        exit(1);
    } else if (bytes_read != sizeof(arp_header)) {
        printf("truncated arp header: only %zd bytes\n", bytes_read);
        exit(1);
    }

    header.hardware_type = ntohs(header.hardware_type);
    header.protocol_type = ntohs(header.protocol_type);
    header.operation = ntohs(header.operation);
    header.sender_protocol_address = ntohl(header.sender_protocol_address);
    header.target_protocol_address = ntohl(header.target_protocol_address);
}

void print_arp(arp_header *header) {
    printf("\tARP:\tHWtype:	%u\n", header->hardware_type);
    printf("\t\thlen:\t%u\n", header->hardware_address_length);
    printf("\t\tplen:\t%u\n", header->protocol_address_length);
    printf("\t\tOP:\t%u", header->operation);
    if (header->operation == ARP_REQUEST) printf(" (ARP request)");
    if (header->operation == ARP_REPLY) printf(" (ARP reply)");
    printf("\n");
    printf("\t\tHardware:\t");
    print_ethernet_address(header->sender_hardware_address);
    printf("\n\t\t\t==>\t");
    print_ethernet_address(header->target_hardware_address);
    printf("\n");
    printf("\t\tProtocol:\t");
    print_ip_address(header->sender_protocol_address);
    printf("\n\t\t\t==>\t");
    print_ip_address(header->target_protocol_address);
    printf("\n");
}
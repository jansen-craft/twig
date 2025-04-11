#ifndef NETWORK_H
#define NETWORK_H

#define IPPROTOCOL_ICMP 1
#define IPPROTOCOL_TCP 6
#define IPPROTOCOL_UDP 17
#define ICMP_ECHO 0

#define ICMP_IOV_LENGTH  5
#include "pcap.h"

struct ipv4_header {
    u_int8_t version_header_length;
    u_int8_t type_of_service;
    u_int16_t total_length;
    u_int16_t identification;
    u_int16_t fragmentation_offset;
    u_int8_t time_to_live;
    u_int8_t protocol;
    u_int16_t checksum;
    u_int32_t source_address;
    u_int32_t destination_address;
};

void parse_ipv4(int fd, ipv4_header &header) {
    ssize_t bytes_read = read(fd, &header, sizeof(ipv4_header));

    if (bytes_read != sizeof(ipv4_header)) {
        printf("truncated ipv4 header: only %zd bytes\n", bytes_read);
        exit(1);
    }

    header.total_length = ntohs(header.total_length);
    header.identification = ntohs(header.identification);
    header.fragmentation_offset = ntohs(header.fragmentation_offset);
    header.checksum = ntohs(header.checksum);
    header.source_address = ntohl(header.source_address);
    header.destination_address = ntohl(header.destination_address);
    header.type_of_service = ntohs(header.type_of_service);

    // magic to void the rest of the bytes in the header that I dont care about
    size_t header_length = (header.version_header_length & 0x0F) * 4;
    if (header_length > sizeof(ipv4_header)) {
        // Skip extra header bytes
        off_t extra_bytes = header_length - sizeof(ipv4_header);
        if (lseek(fd, extra_bytes, SEEK_CUR) == -1) {
            perror("Failed to skip extra IPv4 header bytes");
            exit(1);
        }
    }
}

void print_ipv4(ipv4_header *header) {
    printf("\tIP:\tVers:\t%u\n", header->version_header_length >> 4);
    printf("\t\tHlen:\t%u bytes\n", (header->version_header_length & 0x0F) * 4);  // words -> bytes
    printf("\t\tSrc:\t");
    print_ip_address(header->source_address);
    printf("\n\t\tDest:\t");
    print_ip_address(header->destination_address);
    printf("\n\t\tTTL:\t%u\n", header->time_to_live);
    printf("\t\tFrag Ident:\t%u\n", header->identification);
    printf("\t\tFrag Offset:\t%u\n", (header->fragmentation_offset & 0x1FFF) << 3);
    printf("\t\tFrag DF:\t%s\n", ((header->fragmentation_offset >> 14) & 1) ? "yes" : "no");
    printf("\t\tFrag MF:\t%s\n", ((header->fragmentation_offset >> 13) & 1) ? "yes" : "no");
    printf("\t\tIP CSum:\t%u\n", header->checksum);
    printf("\t\tType:\t0x%x\t", header->protocol);
    if (header->protocol == IPPROTOCOL_TCP) {
        printf("(TCP)");
    } else if (header->protocol == IPPROTOCOL_UDP) {
        printf("(UDP)");
    }
    printf("\n");
}

struct icmp_header {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int32_t data;
};

void parse_icmp(int fd, icmp_header &header) {
    ssize_t bytes_read = read(fd, &header, sizeof(icmp_header));

    if (bytes_read == -1) {
        perror("Error reading ICMP header");
        exit(1);
    } else if (bytes_read != sizeof(icmp_header)) {
        printf("truncated icmp header: only %zd bytes\n", bytes_read);
        exit(1);
    }

    header.type = ntohs(header.type);
    header.code = ntohs(header.code);
    header.checksum = ntohs(header.checksum);
    header.data = ntohl(header.data);
}

void print_icmp(icmp_header *header) {
    printf("\tICMP:\tTYPE:\t\t%u\n", header->type);
    printf("\t\tCODE:\t\t%u\n", header->code);
    printf("\t\tCHECKSUM:\t%u\n", header->checksum);
    printf("\t\tDATA:\t\t%u\n", header->data);
}

void compute_ipv4_checksum(ipv4_header &header) {
    header.checksum = 0;

    uint32_t sum = 0;
    uint16_t *h = (uint16_t *)&header;

    for (size_t i = 0; i < sizeof(ipv4_header) / 2; i++) {
        sum += h[i];
    }

    // carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    header.checksum = ~sum;                              // 1s comp
    if (header.checksum == 0) header.checksum = 0xFFFF;  // pad 1's
}

void compute_icmp_checksum(icmp_header &header, const vector<unsigned char> &payload, size_t payload_length) {
    header.checksum = 0;
    uint32_t sum = 0;

    // header
    uint16_t *h = (uint16_t *)&header;
    for (size_t i = 0; i < sizeof(icmp_header) / 2; i++) {
        sum += h[i];
    }

    // payload
    const uint16_t *p = (const uint16_t *)payload.data();
    size_t len = payload_length;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(uint8_t *)p;  // add leftover

    // carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    header.checksum = ~sum;                              // 1s comp
    if (header.checksum == 0) header.checksum = 0xFFFF;  // pad 1's
}

void icmp_echo_reply(int fd, pcap_packet_header &pph, ethernet_header &eh, ipv4_header &ip4h, icmp_header &ich, vector<unsigned char> &payload) {
    swap(eh.source, eh.destination);
    swap(ip4h.source_address, ip4h.destination_address);
    ich.type = ICMP_ECHO;

    // hokey pokey -> turn yourself around
    ip4h.total_length = ntohs(ip4h.total_length);
    ip4h.identification = ntohs(ip4h.identification);
    ip4h.fragmentation_offset = ntohs(ip4h.fragmentation_offset);
    ip4h.checksum = ntohs(ip4h.checksum);
    ip4h.source_address = ntohl(ip4h.source_address);
    ip4h.destination_address = ntohl(ip4h.destination_address);
    ich.data = ntohl(ich.data);

    compute_icmp_checksum(ich, payload, payload.size());
    compute_ipv4_checksum(ip4h);

    // send it out!
    struct iovec iov[ICMP_IOV_LENGTH] = {
        {&pph, sizeof(pcap_packet_header)},
        {&eh, sizeof(ethernet_header)},
        {&ip4h, sizeof(ipv4_header)},
        {&ich, sizeof(icmp_header)},
        {payload.data(), payload.size()}};

    int rval = writev(fd, iov, ICMP_IOV_LENGTH);
    if (rval == -1) {
        perror("Error writing echo reply");
        exit(1);
    }
}

#endif
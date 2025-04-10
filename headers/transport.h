#define UDP_IOV_LENGTH  5

struct tcp_header {
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int32_t seq;
    u_int32_t ack;
    u_int8_t data_offset;  // 4 bits
    u_int8_t flags;
    u_int16_t window_size;
    u_int16_t checksum;
    u_int16_t urgent_p;
};

void parse_tcp(int fd, tcp_header &header) {
    ssize_t bytes_read = read(fd, &header, sizeof(tcp_header));

    if (bytes_read != sizeof(tcp_header)) {
        printf("truncated tcp header: only %zd bytes\n", bytes_read);
        exit(1);
    }

    header.source_port = ntohs(header.source_port);
    header.destination_port = ntohs(header.destination_port);
    header.seq = ntohl(header.seq);
    header.ack = ntohl(header.ack);
    header.window_size = ntohs(header.window_size);
    header.checksum = ntohs(header.checksum);
    header.urgent_p = ntohs(header.urgent_p);
}

void print_tcp_flags(u_int8_t flags) {
    printf("%c", (flags >> 0) & 1 ? 'F' : '-');
    printf("%c", (flags >> 1) & 1 ? 'S' : '-');
    printf("%c", (flags >> 2) & 1 ? 'R' : '-');
    printf("%c", (flags >> 3) & 1 ? 'P' : '-');
    printf("%c", (flags >> 4) & 1 ? 'A' : '-');
    printf("%c\n", (flags >> 5) & 1 ? 'U' : '-');
}

void print_tcp(tcp_header *header) {
    printf("\tTCP:\tSport:\t%u\n", header->source_port);
    printf("\t\tDport:\t%u\n", header->destination_port);
    printf("\t\tFlags:\t");
    print_tcp_flags(header->flags);
    printf("\t\tSeq:\t%u\n", header->seq);
    printf("\t\tACK:\t%u\n", header->ack);
    printf("\t\tWin:\t%u\n", header->window_size);
    printf("\t\tCSum:\t%u\n", header->checksum);
}

struct udp_header {
    u_int16_t source_port;
    u_int16_t destination_port;
    u_int16_t length;
    u_int16_t checksum;
};

void parse_udp(int fd, udp_header &header) {
    ssize_t bytes_read = read(fd, &header, sizeof(udp_header));

    if (bytes_read != sizeof(udp_header)) {
        printf("truncated udp header: only %zd bytes\n", bytes_read);
        exit(1);
    }

    header.source_port = ntohs(header.source_port);
    header.destination_port = ntohs(header.destination_port);
    header.length = ntohs(header.length);
    header.checksum = ntohs(header.checksum);
}

void print_udp(udp_header *header) {
    printf("\tUDP:\tSport:\t%u\n", header->source_port);
    printf("\t\tDport:\t%u\n", header->destination_port);
    printf("\t\tDGlen:\t%u\n", header->length);
    printf("\t\tCSum:\t%u\n", header->checksum);
}

void compute_udp_checksum(ipv4_header &ipv4, udp_header &udp, const void *payload, uint16_t payload_len) {
    udp.checksum = 0;
    uint32_t sum = 0;

    // Add pseudo-header  - for IPv4
    sum += (ipv4.source_address >> 16) & 0xFFFF;
    sum += (ipv4.source_address) & 0xFFFF;
    sum += (ipv4.destination_address >> 16) & 0xFFFF;
    sum += (ipv4.destination_address) & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += htons(sizeof(udp_header) + payload_len);

    // Add UDP header
    uint16_t *h = (uint16_t *)&udp;
    for (size_t i = 0; i < sizeof(udp_header) / 2; i++) {
        sum += h[i];
    }

    // payload
    const uint16_t *p = (const uint16_t *)payload;
    size_t len = payload_len;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) sum += *(uint8_t *)p;  // add leftovers

    // carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    udp.checksum = ~sum;  // 1s
    if (udp.checksum == 0) udp.checksum = 0xFFFF;
}

void udp_ping(int fd, pcap_packet_header &pph, ethernet_header &eh, ipv4_header &ip4h, udp_header &uh, vector<unsigned char> &payload) {
    swap(ip4h.source_address, ip4h.destination_address);
    swap(uh.source_port, uh.destination_port);

    // hokey pokey -> turn yourself around
    ip4h.total_length = ntohs(ip4h.total_length);
    ip4h.identification = ntohs(ip4h.identification);
    ip4h.fragmentation_offset = ntohs(ip4h.fragmentation_offset);
    ip4h.checksum = ntohs(ip4h.checksum);
    ip4h.source_address = ntohl(ip4h.source_address);
    ip4h.destination_address = ntohl(ip4h.destination_address);

    uh.source_port = ntohs(uh.source_port);
    uh.destination_port = ntohs(uh.destination_port);
    uh.length = ntohs(uh.length);
    uh.checksum = 0;

    // recompute checksum
    compute_ipv4_checksum(ip4h);
    uh.checksum = 0;
    compute_udp_checksum(ip4h, uh, payload.data(), payload.size());

    // send it out!
    struct iovec iov[UDP_IOV_LENGTH] = {
        {&pph, sizeof(pcap_packet_header)},
        {&eh, sizeof(ethernet_header)},
        {&ip4h, sizeof(ipv4_header)},
        {&uh, sizeof(udp_header)},
        {payload.data(), payload.size()}};

    int rval = writev(fd, iov, UDP_IOV_LENGTH);
    if (rval == -1) {
        perror("Error writing echo reply");
        exit(1);
    }
}

void send_time(int fd, pcap_packet_header &pph, ethernet_header &eh, ipv4_header &ip4h, udp_header &uh) {
    time_t now;
    time(&now);

    uint32_t time_protocol_time = htonl((uint32_t)(now + 2208988800));

    ip4h.total_length = ntohs(ip4h.total_length);
    ip4h.identification = ntohs(ip4h.identification);
    ip4h.fragmentation_offset = ntohs(ip4h.fragmentation_offset);
    ip4h.checksum = ntohs(ip4h.checksum);
    ip4h.source_address = ntohl(ip4h.source_address);
    ip4h.destination_address = ntohl(ip4h.destination_address);

    uh.source_port = ntohs(uh.source_port);
    uh.destination_port = ntohs(uh.destination_port);

    swap(ip4h.source_address, ip4h.destination_address);
    swap(uh.source_port, uh.destination_port);

    // update lengths
    pph.captured_length = sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(udp_header) + sizeof(time_protocol_time);
    pph.length = pph.captured_length;
    ip4h.total_length = htons(sizeof(ipv4_header) + sizeof(udp_header) + sizeof(time_protocol_time));

    compute_ipv4_checksum(ip4h);

    uh.length = htons(sizeof(udp_header) + sizeof(time_protocol_time));

    uh.checksum = 0;
    compute_udp_checksum(ip4h, uh, &time_protocol_time, sizeof(time_protocol_time));

    // send out
    struct iovec iov[UDP_IOV_LENGTH] = {
        {&pph, sizeof(pcap_packet_header)},
        {&eh, sizeof(ethernet_header)},
        {&ip4h, sizeof(ipv4_header)},
        {&uh, sizeof(udp_header)},
        {&time_protocol_time, sizeof(time_protocol_time)}};

    int rval = writev(fd, iov, UDP_IOV_LENGTH);
    if (rval == -1) {
        perror("Error writing TIME reply");
    }
}
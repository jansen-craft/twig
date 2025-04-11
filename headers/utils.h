#ifndef UTILS_H
#define UTILS_H

using namespace std;

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

void print_ethernet_address(unsigned char address[6]) {
    for (int i = 0; i < 6; ++i) {
        printf("%02x", address[i]);
        if (i < 5) printf(":");
    }
}

void print_ip_address(u_int32_t address) {
    printf("%i.", (address >> 24) & 0xFF);
    printf("%i.", (address >> 16) & 0xFF);
    printf("%i.", (address >> 8) & 0xFF);
    printf("%i\t", (address >> 0) & 0xFF);
}

char* create_network_filename(const char* input, u_int32_t &ip) {
    const char* mask_location = strchr(input, '_');
    if (!mask_location) {
        char* filename = new char[strlen(input) + 5];
        sprintf(filename, "%s.dmp", input);
        return filename;
    }

    // parse
    ip = 0;
    int octets[4];
    sscanf(input, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
    ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];

    // apply mask
    int mask = atoi(mask_location + 1);
    if (mask < 0 || mask > 32) mask = 32;
    u_int32_t network_ip = ip & (0xFFFFFFFF << (32 - mask));

    octets[0] = (network_ip >> 24) & 0xFF;
    octets[1] = (network_ip >> 16) & 0xFF;
    octets[2] = (network_ip >> 8) & 0xFF;
    octets[3] = network_ip & 0xFF;

    char* filename = new char[32];
    sprintf(filename, "%d.%d.%d.%d%s.dmp", octets[0], octets[1], octets[2], octets[3], mask_location);
    return filename;
}

void parse_packet_content(int fd, std::vector<unsigned char>& buffer, bpf_u_int32 captured_length, unsigned long header_size) {
    if (header_size > captured_length) {
        fprintf(stderr, "Invalid sizes: header (%lu) > captured (%u)\n",
                header_size, captured_length);
        exit(1);
    }

    size_t payload_size = captured_length - header_size;

    const size_t MAX_PAYLOAD_SIZE = 65536;
    if (payload_size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "Payload too large: %zu bytes\n", payload_size);
        exit(1);
    }

    try {
        buffer.resize(payload_size);
    } catch (const std::bad_alloc&) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", payload_size);
        exit(1);
    }

    ssize_t bytes_read = read(fd, buffer.data(), payload_size);

    if (bytes_read == -1) {
        perror("Error reading packet content");
        exit(1);
    } else if (bytes_read != static_cast<ssize_t>(payload_size)) {
        printf("truncated packet: only %zd bytes (expected %u)\n",
               bytes_read + header_size, captured_length);
        exit(1);
    }
}

#endif
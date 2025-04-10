#ifndef PCAP_H
#define PCAP_H

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define LINKTYPE_ETHERNET 1

struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

bool parse_file_header(int fd, pcap_file_header &file_header) {
    bool correct_endian = false;
    ssize_t bytes_read;

    // Read the file header
    bytes_read = read(fd, &file_header, sizeof(pcap_file_header));

    if (bytes_read != sizeof(pcap_file_header)) {
        printf("truncated pcap header: only %zd bytes\n", bytes_read);
        exit(1);
    }

    if (file_header.magic == PCAP_MAGIC) {
        correct_endian = true;
    } else if (ntohl(file_header.magic) == PCAP_MAGIC) {
        correct_endian = false;
        file_header.magic = ntohl(file_header.magic);
    } else {
        printf("invalid magic number: 0x%08x\n", file_header.magic);
        exit(1);
    }

    if (!correct_endian) {
        file_header.version_major = ntohs(file_header.version_major);
        file_header.version_minor = ntohs(file_header.version_minor);
        file_header.linktype = ntohl(file_header.linktype);
    }

    if (!(file_header.version_major == 2) || !(file_header.version_minor == 4)) {
        printf("invalid pcap version: %i.%i\n", file_header.version_major, file_header.version_minor);
        exit(1);
    }

    return correct_endian;
}

void print_file_header(struct pcap_file_header *fh) {
    printf("header magic: %x\n", fh->magic);
    printf("header version: %hu %hu\n", fh->version_major, fh->version_minor);
    printf("header linktype: %u\n\n", fh->linktype);
}

struct pcap_packet_header {
    bpf_u_int32 ts_secs;
    bpf_u_int32 ts_usecs;
    bpf_u_int32 captured_length;
    bpf_u_int32 length;
};

int parse_packet_header(int fd, pcap_packet_header &packet_header, bool correct_endian) {
    ssize_t bytes_read = read(fd, &packet_header, sizeof(pcap_packet_header));

    if (bytes_read == 0) {
        return 0;
    }

    if (bytes_read != sizeof(pcap_packet_header)) {
        printf("truncated packet header: only %zd bytes\n", bytes_read);
        return -1;
    }

    if (!correct_endian) {
        packet_header.captured_length = ntohl(packet_header.captured_length);
        packet_header.length = ntohl(packet_header.length);
        packet_header.ts_secs = ntohl(packet_header.ts_secs);
        packet_header.ts_usecs = ntohl(packet_header.ts_usecs);
    }

    return bytes_read;
}

void print_packet_header(struct pcap_packet_header *header) {
    printf("%10u.%06u000\t%u\t%u\t", header->ts_secs, header->ts_usecs, header->captured_length, header->length);
}

#endif
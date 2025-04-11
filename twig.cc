#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/uio.h>  //writev
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>  // map
#include <vector>

#include "headers/data_link.h"
#include "headers/network.h"
#include "headers/pcap.h"
#include "headers/transport.h"
#include "headers/utils.h"
using namespace std;

int debug = 0;
bool correct_endian = false;

bool usage(const char *prog, bool is_error) {
    printf("Usage: %s [-h] [-d|-dd|-ddd] -i <file>\n", prog);
    return is_error;
}

void process_packet(int in_fd, int out_fd, pcap_packet_header &packet_header, u_int32_t my_ip) {
    ethernet_header ethernet_header;
    vector<unsigned char> payload;

    parse_ethernet_header(in_fd, ethernet_header);
    if (debug) print_ethernet(&ethernet_header);

    int header_size = sizeof(ethernet_header);

    ipv4_header ipv4_header;
    tcp_header tcp_header;
    udp_header udp_header;
    icmp_header icmp_header;
    arp_header arp_header;

    if (ethernet_header.type == ETHERTYPE_IPV4) {
        parse_ipv4(in_fd, ipv4_header);
        if (debug) print_ipv4(&ipv4_header);
        header_size += ((ipv4_header.version_header_length & 0x0F) * 4);
        if (ipv4_header.protocol == IPPROTOCOL_TCP) {
            parse_tcp(in_fd, tcp_header);
            if (debug) print_tcp(&tcp_header);
            header_size += sizeof(tcp_header);
        } else if (ipv4_header.protocol == IPPROTOCOL_UDP) {
            parse_udp(in_fd, udp_header);
            if (debug) print_udp(&udp_header);
            header_size += sizeof(udp_header);
        } else if (ipv4_header.protocol == IPPROTOCOL_ICMP) {
            parse_icmp(in_fd, icmp_header);
            if (debug) print_icmp(&icmp_header);
            header_size += sizeof(icmp_header);
        }
    } else if (ethernet_header.type == ETHERTYPE_ARP) {
        parse_arp(in_fd, arp_header);
        if (debug) print_arp(&arp_header);
        header_size += sizeof(arp_header);
    }

    parse_packet_content(in_fd, payload, packet_header.captured_length, header_size);

    if (ethernet_header.type == ETHERTYPE_IPV4) {
        // just saw IPV4
        if (ipv4_header.protocol == IPPROTOCOL_TCP) {
            // just saw TCP
        } else if (ipv4_header.protocol == IPPROTOCOL_UDP) {
            // just saw UDP
            if (udp_header.destination_port == ECHO_PORT) {
                if (debug >= 1){
                    printf("responding to UDP ECHO request!\n");
                }
                udp_ping(out_fd, packet_header, ethernet_header, ipv4_header, udp_header, payload);
            } else if (udp_header.destination_port == TIME_PORT) {
                if (debug >= 1){
                    printf("responding to UDP TIME request!\n");
                }
                send_time(out_fd, packet_header, ethernet_header, ipv4_header, udp_header);
            }
        } else if (ipv4_header.protocol == IPPROTOCOL_ICMP && ipv4_header.destination_address == my_ip) {
            if (debug >= 1){
                printf("responding to ICMP ECHO request!\n");
            }
            icmp_echo_reply(out_fd, packet_header, ethernet_header, ipv4_header, icmp_header, payload);
        }
    } else if (ethernet_header.type == ETHERTYPE_ARP) {
        // just saw ARP
    }
}

int main(int argc, char *argv[]) {
    char *filename = NULL;
    u_int32_t ip = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) filename = create_network_filename(argv[++i], ip);
        else if (!strcmp(argv[i], "-h"))    return usage(argv[0], 0);
        else if (!strcmp(argv[i], "-d"))    debug = 1;
        else if (!strcmp(argv[i], "-dd"))   debug = 2;
        else if (!strcmp(argv[i], "-ddd"))  debug = 3;
        else    return usage(argv[0], 1);
    }

    if (!filename) return usage(argv[0], 1);

    int in_fd = open(filename, O_RDONLY);
    if (in_fd == -1) {
        perror("Error opening input file");
        return 1;
    }

    int out_fd = open(filename, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (out_fd == -1) {
        perror("Error opening output file");
        return 1;
    }

    // pcap file header
    struct pcap_file_header file_header;
    correct_endian = parse_file_header(in_fd, file_header);
    print_file_header(&file_header);

    // parse each packet
    int unsucessful_parse_attempts = 0;
    while (1) {
        off_t current_pos = lseek(in_fd, 0, SEEK_CUR);
        if (current_pos == -1) {
            perror("Error getting current file position");
            sleep(2);
            continue;
        }

        pcap_packet_header packet_header;
        ssize_t bytes_read = parse_packet_header(in_fd, packet_header, correct_endian);

        if (bytes_read == 0) {
            if (++unsucessful_parse_attempts == 5) {
                printf("listening...\n");
            }
            lseek(in_fd, current_pos, SEEK_SET);
            usleep(10000);
            continue;
        }

        unsucessful_parse_attempts = 0;
        if (debug) print_packet_header(&packet_header);        

        process_packet(in_fd, out_fd, packet_header, ip);
    }
}

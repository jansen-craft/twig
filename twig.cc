#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sys/uio.h> //writev
#include "headers/utils.h"
#include "headers/pcap.h"
#include "headers/data_link.h"
#include "headers/network.h"
#include "headers/transport.h"
using namespace std;

int debug = 0;
bool correct_endian = false;

int main(int argc, char *argv[]){
	struct pcap_file_header file_header;
	char *filename = NULL;
	int in_fd = STDIN_FILENO; 

	if (argc >= 3 && (strcmp(argv[1], "-i") == 0)){
		filename = create_network_filename(argv[2]);
	} else if ((argc == 3) && (strcmp(argv[1], "-d") == 0)){
		debug = 1;
		filename = argv[2];
	} else if ((argc == 3) && (strcmp(argv[1], "-n") == 0)){
		filename = argv[2];
	} else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[0]);
            fprintf(stdout, "Usage: %s [-d] filename\n", argv[0]);
    }

	printf("DEBUG LEVEL: %i\n", debug);

	if (strcmp(filename, "-") != 0) {
        in_fd = open(filename, O_RDONLY | O_CREAT | O_APPEND, 0644);
        if (in_fd == -1) {
			printf("filename: %s\n", filename);
            perror("Error opening input file");
            return 1;
        }
    }

	int out_fd = open(filename, O_RDWR | O_CREAT | O_APPEND, 0644);

	if (out_fd == -1) {
		perror("Error opening output file");
		close(out_fd);
		return 1;
	}

	correct_endian = parse_file_header(in_fd, file_header);
	print_file_header(&file_header);

	int unsucessful_parse_attempts = 0;

		while (1){
			pcap_packet_header packet_header;
			ethernet_header ethernet_header;
			vector<unsigned char> payload;

			off_t current_pos = lseek(in_fd, 0, SEEK_CUR);
			if (current_pos == -1) {
				perror("Error getting current file position");
				sleep(2);
				continue;
			}

			ssize_t bytes_read = parse_packet_header(in_fd, packet_header, correct_endian);
	
			if (bytes_read == 0) {
				unsucessful_parse_attempts++;
				if (unsucessful_parse_attempts == 5){
					printf("listening...\n");
				}
				lseek(in_fd, current_pos, SEEK_SET);
				usleep(10000);
				continue;
			}

			unsucessful_parse_attempts = 0;

			parse_ethernet_header(in_fd, ethernet_header);
			print_ethernet(&packet_header, &ethernet_header);

			int header_size = sizeof(ethernet_header);

			ipv4_header ipv4_header;
			tcp_header tcp_header;
			udp_header udp_header;
			icmp_header icmp_header;
			arp_header arp_header;

			if (ethernet_header.type == ETHERTYPE_IPV4){
				parse_ipv4(in_fd, ipv4_header);
				print_ipv4(&ipv4_header);
				header_size += ((ipv4_header.version_header_length & 0x0F) * 4);
				if (ipv4_header.protocol == IPPROTOCOL_TCP){
					parse_tcp(in_fd, tcp_header);
					print_tcp(&tcp_header);
					header_size += sizeof(tcp_header);
				} else if (ipv4_header.protocol == IPPROTOCOL_UDP){
					parse_udp(in_fd, udp_header);
					print_udp(&udp_header);
					header_size += sizeof(udp_header);
				} else if (ipv4_header.protocol == IPPROTOCOL_ICMP){
					parse_icmp(in_fd, icmp_header);
					print_icmp(&icmp_header);
					header_size += sizeof(icmp_header);
				}
			} else if (ethernet_header.type == ETHERTYPE_ARP){
				parse_arp(in_fd, arp_header);
				print_arp(&arp_header);
				header_size += sizeof(arp_header);
			}

			parse_packet_content(in_fd, payload, packet_header.captured_length, header_size);

			if (ethernet_header.type == ETHERTYPE_IPV4){
				// just saw IPV4
				if (ipv4_header.protocol == IPPROTOCOL_TCP){
					// just saw TCP
				} else if (ipv4_header.protocol == IPPROTOCOL_UDP){
					// just saw UDP
					if (udp_header.destination_port == 7){
						printf("ECHO Echo echo echo...\n");
						udp_ping(out_fd, packet_header, ethernet_header, ipv4_header, udp_header, payload);
					} else if (udp_header.destination_port == 37){
						send_time(out_fd, packet_header, ethernet_header, ipv4_header, udp_header);
					}
				} else if (ipv4_header.protocol == IPPROTOCOL_ICMP && ipv4_header.destination_address == 2887745538){ // 172.31.128.2
					icmp_echo_reply(out_fd, packet_header, ethernet_header, ipv4_header, icmp_header, payload);
				}
			} else if (ethernet_header.type == ETHERTYPE_ARP){
				// just saw ARP
			}
		}
}

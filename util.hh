#ifndef UTIL_H_
#define UTIL_H_

#include <netinet/tcp.h>


struct checkSumIpHeader {
    int saddr;
    int daddr;
    char zero;
    char protocol;
    short tcp_len;
    struct tcphdr tcp;
};

char* create_tcp_syn(const char* source, const char* dest, short dest_port, short source_port, int* packet_size);
char* create_udp_probe(const char* source, const char* dest, short dest_port, short source_port, int* packet_size);
int create_socket(int protocol, char* interface);
struct sockaddr_in create_target(char* destination);
unsigned short calculate_tcp_checksum(unsigned short *addr, int count);

#endif // UTIL_H_

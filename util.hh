#ifndef UTIL_H_
#define UTIL_H_

#include <netinet/tcp.h>

/**
 * A pseudo-header used for computing the TCP checksum.
 */
struct checkSumIpHeader {
    int saddr;
    int daddr;
    char zero;
    char protocol;
    short tcp_len;
    struct tcphdr tcp;
};

/**
 * Returns a TCP SYN segment with given parameters of length packet_size
 */
char* create_tcp_syn(const char* source, const char* dest, short dest_port, short source_port, int* packet_size);
/**
 * Returns an empty UDP segment with given parameters of length packet_size.
 */
char* create_udp_probe(const char* source, const char* dest, short dest_port, short source_port, int* packet_size);
/**
 * Creates a network socket for given interface and protocol.
 */
int create_socket(int protocol, char* interface);
/**
 * Creates a sockaddr structure with given parameters.
 */
struct sockaddr_in create_target(char* destination);
/**
 * Computes the internet checksum for given array of size count.
 *
 * Taken RFC 1071 [https://www.rfc-editor.org/rfc/rfc1071].
 * This function is not subject to the GPL.
 */
unsigned short calculate_tcp_checksum(unsigned short *addr, int count);

#endif // UTIL_H_

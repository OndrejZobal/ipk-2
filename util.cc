#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <cstring>
#include <iostream>
#include <net/if.h>

#include "util.hh"

using namespace std;

char* create_tcp_syn(const char* source, const char* dest, short dest_port, short source_port, int* packet_size) {
    *packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    char* buffer = static_cast<char*>(malloc(*packet_size));
    memset(buffer, 0, *packet_size);

    struct iphdr* ip_header = (struct iphdr*)(buffer);
    struct tcphdr* tcp_header = (struct tcphdr*)(buffer + sizeof(struct iphdr));

    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = *packet_size;
    ip_header->id = rand() % 0xffff;
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->saddr = inet_addr(source);
    ip_header->daddr = inet_addr(dest);
    ip_header->check = htons(htons(~(tcp_header->check)) + htons(~(ip_header->protocol)) + htons(sizeof(tcp_header) + sizeof(ip_header)));

    tcp_header->source = htons(source_port);
    tcp_header->dest = htons(dest_port);
    tcp_header->seq = rand();
    tcp_header->doff = 5;
    tcp_header->syn = 1;
    tcp_header->window = htons(8192);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    struct checkSumIpHeader checkHeader;
    checkHeader.saddr = ip_header->saddr;
    checkHeader.daddr = ip_header->daddr;
    checkHeader.zero = '\0';
    checkHeader.protocol = ip_header->protocol;
    checkHeader.tcp_len = htons(sizeof(struct tcphdr));
    memcpy(&(checkHeader.tcp), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = calculate_tcp_checksum((unsigned short*) &checkHeader, sizeof(struct checkSumIpHeader));

    return buffer;
}

char* create_udp_probe(const char* source, const char* dest, short dest_port, short source_port, int* packet_size) {
    *packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
    char* buffer = static_cast<char*>(malloc(*packet_size));
    memset(buffer, 0, *packet_size);

    struct iphdr* ip_header = (struct iphdr*)(buffer);
    struct udphdr* udp_header = (struct udphdr*)(((char*)buffer) + sizeof(struct iphdr));

    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = *packet_size;
    ip_header->id = rand() % 0xffff;
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->saddr = inet_addr(source);
    ip_header->daddr = inet_addr(dest);
    ip_header->check = htons(htons(~(udp_header->check)) + htons(~(ip_header->protocol)) + htons(sizeof(udp_header) + sizeof(ip_header)));

    udp_header->source = htons(source_port);
    udp_header->dest = htons(dest_port);
    udp_header->len = htons(sizeof(struct udphdr));
    udp_header->check = 0;

    return buffer;
}

int create_socket(int protocol, char* interface) {
    int raw_socket = socket(AF_INET, SOCK_RAW, protocol);
    if (raw_socket == -1) {
        cerr << "Could not create raw socket: " << strerror(errno) << endl;
        exit(1);
    }
    int on = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
        cerr << "Could not set IP_HDRINCL: " << strerror(errno) << endl;
        exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), interface);
    if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0){
        cerr << "Could not bind interface" << endl;
        exit(1);
    }

    return raw_socket;
}

struct sockaddr_in create_target(char* destination) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(destination);
    return target;
}

// The following function was taken from RFC 1071 [https://www.rfc-editor.org/rfc/rfc1071]
// and is not subject to the GPL.
unsigned short calculate_tcp_checksum(unsigned short *addr, int count) {
    /* Compute Internet Checksum for "count" bytes
    *         beginning at location "addr".
    */
    long sum = 0;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += *addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

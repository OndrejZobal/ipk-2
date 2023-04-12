#include "scanner.hh"
#include <iostream>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

char* make_tcp_packet(const char* source_ip,
                           const char* dest_ip,
                           int dest_port, int* packet_length) {
    struct tcphdr tcp_header;
    memset(&tcp_header, 0, sizeof(tcp_header));
    tcp_header.source = htons(rand() % (0xffff - 1024) + 1024);
    tcp_header.dest = htons(dest_port);
    tcp_header.seq = rand();
    tcp_header.doff = 5;
    tcp_header.syn = 1;
    tcp_header.window = htons(8192);
    tcp_header.check = 0;
    tcp_header.urg_ptr = 0;

    *packet_length = (sizeof(struct iphdr) + sizeof(tcp_header)) * sizeof(char);
    char* packet = (char*) malloc(*packet_length);
    memset(packet, 0, *packet_length);
    struct iphdr *ip_header = (struct iphdr *) packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(packet);
    ip_header->id = rand() % 0xffff;
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = inet_addr(dest_ip);
    memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(tcp_header));
    tcp_header.check = 0;
    tcp_header.check = htons(htons(~(tcp_header.check)) + htons(~(ip_header->protocol)) + htons(sizeof(tcp_header) + sizeof(ip_header)));

    return packet;
}

int main() {
    int packet_length;
    char* make_packet = make_tcp_packet("192.168.2.96", "192.168.2.2", 80, &packet_length);
    (void) make_packet;
}

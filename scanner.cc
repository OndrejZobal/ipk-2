#include "scanner.hh"
#include <iostream>
#include <sys/epoll.h>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include<map>
#include<string>
#include <thread>
#include <vector>
#include <chrono>
#include <time.h>
#include <chrono>
#include <mutex>
#include <atomic>

using namespace std;
enum class PortStatus {silent, open, closed};
enum class PortType { tcp, udp };

using PortMap = map<unsigned short, PortStatus>;
using PortEnumer = vector<pair<PortType, unsigned short>>;

// This is the timeout in ms between sending each packet.
// I have had good results with pauses as little as 4 ms
// so this should work even on slower devices.
#define SEND_PAUSE_MS 20

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

struct checkSumIpHeader {
    int saddr;
    int daddr;
    char zero;
    char protocol;
    short tcp_len;
    struct tcphdr tcp;
};

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

int create_socket(int protocol) {
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

    return raw_socket;
}

struct sockaddr_in create_target(char* destination) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = inet_addr(destination);
    return target;
}

void send_tcp_packet(char* source, char* destination, int d_port, int s_port, int raw_socket, struct sockaddr_in target) {
    int packet_size;
    char* tcp_packet = create_tcp_syn(source, destination, d_port, s_port, &packet_size);
    int ret;
    if ((ret = sendto(raw_socket, tcp_packet, packet_size, 0, (struct sockaddr *) &target, sizeof(target))) == -1) {
    }
    free(tcp_packet);
}

void send_udp_packet(char* source, char* destination, int d_port, int s_port, int raw_socket, struct sockaddr_in target) {
    int packet_size;
    char* udp_packet = create_udp_probe(source, destination, d_port, s_port, &packet_size);
    int ret;
    if ((ret = sendto(raw_socket, udp_packet, packet_size, 0, (struct sockaddr *) &target, sizeof(target))) == -1) {
    }
    free(udp_packet);
}

int process_tcp_response(struct tcphdr* tcp_header, unsigned short s_port, PortMap& port_map, std::mutex& port_map_mutex) {
    if (ntohs(tcp_header->dest) != s_port) {
        return 0;
    }

    PortStatus status;
    if (tcp_header->syn && tcp_header->ack) {
        status = PortStatus::open;
    } else {
        status = PortStatus::closed;
    }

    std::lock_guard<std::mutex> guard(port_map_mutex);
    if (port_map.find(ntohs(tcp_header->source)) != port_map.end()) {
        port_map[ntohs(tcp_header->source)] = status;
        return 1;
    }

    return 0;
}

int process_icmp_response(struct icmphdr* icmp_header, unsigned short s_port, PortMap& udp_port_map, std::mutex& port_map_mutex) {
    if (icmp_header->type != ICMP_DEST_UNREACH || icmp_header->code != ICMP_PORT_UNREACH) {
        return 0;
    }

    // IP header of the original message is stored after 8 bytes
    struct iphdr* ip_header = (struct iphdr*) (((char*)icmp_header) + 8);
    struct udphdr* udp_header = (struct udphdr*) (((char*)ip_header) + sizeof(iphdr));

    if (ip_header->protocol != IPPROTO_UDP) {
        return 0;
    }

    if (udp_header->source != htons(s_port)) {
        return 0;
    }

    std::lock_guard<std::mutex> guard(port_map_mutex);
    if (udp_port_map.find(ntohs(udp_header->dest)) != udp_port_map.end()) {
        udp_port_map[ntohs(udp_header->dest)] = PortStatus::closed;
        return 1;
    }

    return 0;
}

void recive_packet(int raw_socket,
                   unsigned short s_port,
                   PortMap& port_map,
                   std::mutex& port_map_mutex,
                   int limit_ms,
                   atomic<bool>* sent_all,
                   int protocol) {
    if (!port_map.size()) return;

    char response[1024 * 1024];
    memset(response, 0, sizeof(response));
    struct sockaddr_in sender;
    socklen_t sender_size = sizeof(sender);

    struct iphdr *ip_header = (struct iphdr *) response;
    char* next_header = (char *) (response + sizeof(struct iphdr));

    struct timeval timeout;
    chrono::time_point start = chrono::high_resolution_clock::now();
    int ms = -1;
    int recived = 0;

    do {
        // Doing this just so we can stop checking this atom once we se it as true once.
        if (ms == -1) {
            if (sent_all->load()) {
                start = chrono::high_resolution_clock::now();
                ms = 0;
            }
            else {
                // Timeout before we check again
                timeout.tv_sec = 0;
                timeout.tv_usec = 50;
            }
        }
        if (ms != -1) {
            // After we get a confirmation that the other thread sent all packets we can start the countdown on the
            // timeout.
            ms = chrono::duration_cast<std::chrono::milliseconds>(chrono::high_resolution_clock::now() - start).count();
            int remain = limit_ms - ms;

            if (remain <= 0 || (int) port_map.size() <= recived) {
                break;
            }

            timeout.tv_sec = remain / 1000; // convert to seconds
            timeout.tv_usec = (remain % 1000) * 1000; // convert remaining milliseconds to microseconds
        }

        setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        int response_size = recvfrom(raw_socket, response, sizeof(response), 0, (struct sockaddr *) &sender, &sender_size);
        if (response_size == -1) continue;

        if (ip_header->protocol == IPPROTO_TCP && protocol == IPPROTO_TCP) {
            recived += process_tcp_response((struct tcphdr*) next_header, s_port, port_map, port_map_mutex);
        }
        else if (ip_header->protocol == IPPROTO_ICMP && protocol == IPPROTO_ICMP) {
            recived += process_icmp_response((struct icmphdr*) next_header, s_port, port_map, port_map_mutex);
        }

    } while (ms < limit_ms);
}

void print_result(PortEnumer port_num, PortMap tcp_port_status, PortMap udp_port_status) {
    cout << "PORT STATE" << endl;
    for (pair i : port_num) {

        PortType type = i.first;
        unsigned short index = i.second;

        char* protocol;
        switch (type) {
            case PortType::tcp:
                protocol = (char*) "tcp";
                break;
            case PortType::udp:
                protocol = (char*) "udp";
                break;
        }

        char* status;
        if (type == PortType::tcp) {
            switch (tcp_port_status[index]) {
                case PortStatus::open:
                    status = (char*) "open";
                    break;
                case PortStatus::silent:
                    status = (char*) "filtered";
                    break;
                case PortStatus::closed:
                    status = (char*) "closed";
                    break;
            }
        }

        else if (type == PortType::udp) {
            switch(udp_port_status[index]) {
                case PortStatus::open:
                    status = (char*) "open";
                    break;
                case PortStatus::closed:
                    status = (char*) "closed";
                    break;
                default:;
            }
        }

        cout << i.second << "/" << protocol << " " << status << endl;
    }

}

void send_all_packets(char* source, char* destination, int s_port, int raw_socket, vector<pair<PortType, unsigned short>> port_num) {
    struct sockaddr_in target = create_target(destination);

    for (auto port : port_num) {
        PortType type = port.first;
        unsigned short d_port = port.second;

        usleep(SEND_PAUSE_MS);

        if (type == PortType::tcp) {
            send_tcp_packet(source, destination, d_port, s_port, raw_socket, target);
        }
        else if (type == PortType::udp) {
            send_udp_packet(source, destination, d_port, s_port, raw_socket, target);
        }
    }
}

int main() {
    srand(time(NULL));

    char* source = (char*) "192.168.2.128";
    char* destination = (char*) "192.168.2.2";
    unsigned short s_port = rand() % (0xffff - 1024) + 1024;
    int limit_ms = 10000;

    int raw_socket = create_socket(IPPROTO_TCP);
    int icmp_socket = create_socket(IPPROTO_ICMP);

    PortEnumer port_num;
    PortMap tcp_port_status;
    PortMap udp_port_status;

    for (int i = 1; i <= 124; ++i) {
        port_num.push_back(pair(PortType::tcp, i));
        tcp_port_status.insert({i, PortStatus::silent});
    }
    for (int i = 40; i <= 45; ++i) {
        port_num.push_back(pair(PortType::udp, i));
        udp_port_status.insert({i, PortStatus::open});
    }

    // port_num.push_back(pair(PortType::udp, 53));
    // udp_port_status.insert({53, PortStatus::open});

    atomic<bool> sent_all { false };

    std::mutex tcp_mutex;
    std::mutex udp_mutex;

    // The recvfrom function needs to run in it's ow thread because sending a large amounts of packets
    // takes a really long time and we could miss some responses.
    std::thread tcp_thread {recive_packet, raw_socket, s_port, ref(tcp_port_status), ref(tcp_mutex), limit_ms, &sent_all, IPPROTO_TCP};
    std::thread udp_thread {recive_packet, icmp_socket, s_port, ref(udp_port_status), ref(udp_mutex), limit_ms, &sent_all, IPPROTO_ICMP};

    send_all_packets(source, destination, s_port, raw_socket, port_num);
    sent_all.store(true);

    if (tcp_thread.joinable())
        tcp_thread.join();
    if (udp_thread.joinable())
        udp_thread.join();

    print_result(port_num, tcp_port_status, udp_port_status);

    return 0;
}

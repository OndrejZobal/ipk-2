#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string>
#include <thread>
#include <chrono>
#include <time.h>
#include <mutex>
#include <atomic>
#include <sys/ioctl.h>
#include <net/if.h>

#include "scanner.hh"
#include "cmdline.hh"
#include "util.hh"


using namespace std;

/**
 * Sends TCP packet using a raw socket. Source and Destination addreses are specified in the numbers-and-dots notation.
 * */
void send_tcp_packet(char* source, char* destination, int d_port, int s_port, int raw_socket, struct sockaddr_in target) {
    int packet_size;
    char* tcp_packet = create_tcp_syn(source, destination, d_port, s_port, &packet_size);
    int ret;
    if ((ret = sendto(raw_socket, tcp_packet, packet_size, 0, (struct sockaddr *) &target, sizeof(target))) == -1) {
    }
    free(tcp_packet);
}

/**
 * Sends UDP packet using a raw socket. Source and Destination addreses are specified in the numbers-and-dots notation.
 * */
void send_udp_packet(char* source, char* destination, int d_port, int s_port, int raw_socket, struct sockaddr_in target) {
    int packet_size;
    char* udp_packet = create_udp_probe(source, destination, d_port, s_port, &packet_size);
    int ret;
    if ((ret = sendto(raw_socket, udp_packet, packet_size, 0, (struct sockaddr *) &target, sizeof(target))) == -1) {
    }
    free(udp_packet);
}

/**
 * Parses a TCP header, if it is relevant to scanning record it in port_map.
 * */
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

/**
 * Parses an ICMP header, if it is relevant to scanning record it in port_map.
 * */
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

/**
 * Listens for incoming packets and if they are a response to one of our probing segments,
 * records it's findings in port_map.
 * While sent_all is set to false, the function will receive indefinitely, once sent_all
 * turns true, the scanning will continue for limit_ms microseconds.
 * */
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

/**
 * Outputs information stored in TCP and UDP port maps to standard output.
 * */
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

/**
 * Sends one probing packet through the supplied raw socket for every entry in port_num.
 * Source and destination are specified using the numbers-and-dots notation.
 * */
void send_all_packets(char* source, char* destination, int s_port, int raw_socket, PortEnumer port_num) {
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

int main(int argc, char** argv) {
    (void) argc;
    srand(time(NULL));

    string source;
    string hostname;
    int limit_ms = 5000;
    string interface;

    PortEnumer port_num;
    PortMap tcp_port_status;
    PortMap udp_port_status;

    // Configuring program from command line arguments.
    process_cmdline_args(argv, hostname, limit_ms, interface, port_num, tcp_port_status, udp_port_status);

    // Converting supplied user-supplied hostname to an IP address.
    string destination = host_to_ip(hostname);
    // Picking a random 16-bit number for the port and making sure we don't colide
    // with any well-known ports.
    unsigned short s_port = rand() % (0xffff - 1024) + 1024;

    // Quaring address of selected network interface.
    get_source_ip((char*) interface.c_str(), source);

    // Creating raw sockets.
    // The TCP socket can send UDP packets just fine.
    int raw_socket = create_socket(IPPROTO_TCP, (char*) interface.c_str());
    int icmp_socket = create_socket(IPPROTO_ICMP, (char*) interface.c_str());

    // A flag used for communicating between threads that the sending of packets have been complete
    atomic<bool> sent_all { false };

    // Mutexes for locking PortMaps.
    std::mutex tcp_mutex;
    std::mutex udp_mutex;

    // The recvfrom function needs to run in it's ow thread because sending a large amounts of packets
    // takes a really long time and we could miss some responses.
    std::thread tcp_thread {recive_packet, raw_socket, s_port, ref(tcp_port_status), ref(tcp_mutex), limit_ms, &sent_all, IPPROTO_TCP};
    std::thread udp_thread {recive_packet, icmp_socket, s_port, ref(udp_port_status), ref(udp_mutex), limit_ms, &sent_all, IPPROTO_ICMP};

    // Sending probing packets.
    send_all_packets((char*) source.c_str(), (char*) destination.c_str(), s_port, raw_socket, port_num);
    sent_all.store(true);

    // Waiting for receiving threads.
    if (tcp_thread.joinable())
        tcp_thread.join();
    if (udp_thread.joinable())
        udp_thread.join();

    // We won't need the sockets anymore.
    close(raw_socket);
    close(icmp_socket);

    // Printing results.
    cout << "Interesting ports on " << hostname << " (" << destination << ")" << endl;
    print_result(port_num, tcp_port_status, udp_port_status);

    return 0;
}

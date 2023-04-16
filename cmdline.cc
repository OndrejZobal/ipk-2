#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <cstring>

#include "cmdline.hh"

using namespace std;

void list_interfaces() {
    struct ifaddrs *interfaces, *first;
    char addr_str[INET_ADDRSTRLEN];

    if (getifaddrs(&first) == -1) {
        cerr << "Canouln't list network interfaces" << endl;
        exit(1);
    }
    interfaces = first;

    while (interfaces != NULL) {
        if (interfaces->ifa_addr == NULL || interfaces->ifa_addr->sa_family != AF_INET) {
            interfaces = interfaces->ifa_next;
            continue;
        }

        struct sockaddr_in* sa = (struct sockaddr_in *)interfaces->ifa_addr;
        if (inet_ntop(AF_INET, &(sa->sin_addr), addr_str, INET_ADDRSTRLEN) == NULL) {
            cerr << "Couldn't find address of " << interfaces->ifa_name <<  endl;
            exit(1);
        }

        cout << interfaces->ifa_name << "\t" << addr_str << endl;
        interfaces = interfaces->ifa_next;
    }

    freeifaddrs(first);
}

void get_source_ip(const char* interface, string& ip) {
    struct ifaddrs *interfaces, *first;
    char addr_str[INET_ADDRSTRLEN];

    if (getifaddrs(&first) == -1) {
        cerr << "Canouln't list network interfaces" << endl;
        exit(1);
    }
    interfaces = first;

    while (interfaces != NULL) {
        if (interfaces->ifa_addr == NULL || interfaces->ifa_addr->sa_family != AF_INET) {
            interfaces = interfaces->ifa_next;
            continue;
        }

        if (strcmp(interfaces->ifa_name, interface)) {
            interfaces = interfaces->ifa_next;
            continue;
        }

        struct sockaddr_in* sa = (struct sockaddr_in *)interfaces->ifa_addr;
        if (inet_ntop(AF_INET, &(sa->sin_addr), addr_str, INET_ADDRSTRLEN) == NULL) {
            cerr << "Couldn't find address of " << interfaces->ifa_name <<  endl;
            exit(1);
        }
        ip = string(addr_str);
        break;
    }

    freeifaddrs(first);
}

string host_to_ip(string hostname) {
    struct addrinfo hints, *res;
    char ipstr[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname.c_str(), NULL, &hints, &res)) {
        cerr << "Couldn't convert " << hostname << " to IPv4 address" << endl;
        exit(1);
    }

    struct sockaddr_in* sock_addr = (struct sockaddr_in*)res->ai_addr;
    void* addr = &(sock_addr->sin_addr);
    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);

    freeaddrinfo(res);

    return string(ipstr);
}

void parse_range(char* range, PortType type, PortEnumer& port_enumeration, PortMap& port_map) {
    string acc = "";

    bool trailing_separator;
    bool is_range = false;
    bool is_list = false;
    int bound;

    PortStatus status = (type == PortType::tcp) ? PortStatus::silent : PortStatus::open;

    for (char c = *range; c != '\0'; c = *(++range)) {
        trailing_separator = false;
        if ('0' <= c && c <= '9') {
            acc += c;
        }
        // List of ports ex. '10,20,22'
        else if (c == ',') {
            is_list = true;
            if (is_range) {
                cout << "Cannot combine range and list"  << endl;
                exit(1);
            }
            trailing_separator = true;

            cerr << "AAA "  << acc <<  endl;
            int port = stoi(acc);
            acc = "";

            port_enumeration.push_back(pair(type, port));
            port_map.insert({port, status});

            cerr << "signel port " << port << endl;
        }
        // Range ex. '10-100'
        else if (c == '-') {
            trailing_separator = true;
            // If '-' was specified twice.
            if (is_range || is_list) {
                cerr << "Invalid syntax for port range" << endl;
                exit(1);
            }

            is_range = true;
            bound = stoi(acc);
            acc = "";
        }
        else {
            cerr << c << endl;
            cerr << "Invalid port" << endl;
            exit(1);
        }
    }


    if (trailing_separator) {
        cerr << "Invalid syntax port" << endl;
        exit(1);
    }

    // Inserting ports in specified range
    if (is_range) {
        int other_bound = stoi(acc);
        if (bound >= other_bound) {
            cerr << "Invalid range" << endl;
            exit(1);
        }

        for (int i = bound; i <= other_bound; i++) {
            port_enumeration.push_back(pair(type, i));
            port_map.insert({i, status});
            cerr << "signel port " << i << endl;
        }
    }
    // Inserting last port from list
    else {
        int port = stoi(acc);
        acc = "";

        port_enumeration.push_back(pair(type, port));
        port_map.insert({port, status});

        cerr << "signel port " << port << endl;
    }
}

void process_cmdline_args(char** argv,
                          string& hostname,
                          int& limit_ms,
                          string& interface,
                          PortEnumer& port_enumeration,
                          PortMap& tcp_port_map,
                          PortMap& udp_port_map) {
    string prog_name = *argv;
    hostname = "";
    interface = "";

    while (*(++argv) != nullptr) {
        if (!strcmp(*argv, "-i") || !strcmp(*argv, "--interface")) {
            if (*(++argv) == nullptr) {
                list_interfaces();
                exit(1);
            }
            interface = string(*argv);
        }
        else if (!strcmp(*argv, "-t") || !strcmp(*argv, "--pt")) {
            if (*(++argv) == nullptr) {
                cerr << "Missing argument!" << endl;
                exit(1);
            }
            try {
                parse_range(*argv, PortType::tcp, port_enumeration, tcp_port_map);
            }
            catch (std::invalid_argument&) {
                cerr << "Bad port" << endl;
                exit(1);
            }
        }
        else if (!strcmp(*argv, "-u") || !strcmp(*argv, "--pu")) {
            if (*(++argv) == nullptr) {
                cerr << "Missing argument!" << endl;
                exit(1);
            }
            try {
                parse_range(*argv, PortType::udp, port_enumeration, udp_port_map);
            }
            catch (std::invalid_argument&) {
                cerr << "Bad port" << endl;
                exit(1);
            }
        }
        else if (!strcmp(*argv, "-w") || !strcmp(*argv, "--wait")) {
            if (*(++argv) == nullptr) {
                cerr << "Missing argument!" << endl;
                exit(1);
            }
            limit_ms = stoi(*argv) * 1000;
            if (limit_ms < 0) {
                cerr << "Can specify negative limits" << endl;
                exit(1);
            }
        }
        else {
            if (hostname != "") {
                cerr << "Hostname already specified" << endl;
                exit(1);
            }

            hostname = string(*argv);
        }
    }

    if (interface == "") {
        list_interfaces();
        exit(1);
    }

    if (hostname == "") {
        cerr << "No hostname given" << endl;
        exit(1);
    }
}

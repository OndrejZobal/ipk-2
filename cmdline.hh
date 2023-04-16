#ifndef CMDLINE_H_
#define CMDLINE_H_

#include <string>
#include "dtypes.hh"

void list_interfaces();
void get_source_ip(const char* interface, std::string& ip);
std::string host_to_ip(std::string hostname);
void parse_range(std::string range, PortEnumer port_enumeration, PortMap port_map);
void process_cmdline_args(char** argv, std::string& hostname, int& limit_ms, std::string& interface, PortEnumer& port_enumeration, PortMap& tcp_port_map, PortMap& udp_port_map);

#endif // CMDLINE_H_

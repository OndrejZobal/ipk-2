#ifndef CMDLINE_H_
#define CMDLINE_H_

#include <string>
#include "dtypes.hh"

/**
 * Prints a list of available interfaces and their addresses.
 */
void list_interfaces();
/**
 * Copies address of a given interface into ip.
 */
void get_source_ip(const char* interface, std::string& ip);
/**
 * Returns an ip address in the numbers-and-dots notation of a given hostname
 */
std::string host_to_ip(std::string hostname);
/**
 * A helper function used to convert ports from the command line (ex. 10,20,30 100-200).
 */
void parse_range(std::string range, PortEnumer port_enumeration, PortMap port_map);
/**
 * Reads argv and sets given variables accordingly.
 */
void process_cmdline_args(char** argv, std::string& hostname, int& limit_ms, std::string& interface, PortEnumer& port_enumeration, PortMap& tcp_port_map, PortMap& udp_port_map);

#endif // CMDLINE_H_

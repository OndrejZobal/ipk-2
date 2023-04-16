#ifndef DTYPES_H_
#define DTYPES_H_

#include <map>
#include <vector>

enum class PortStatus {silent, open, closed};
enum class PortType { tcp, udp };

using PortMap = std::map<unsigned short, PortStatus>;
using PortEnumer = std::vector<std::pair<PortType, unsigned short>>;

#endif // DTYPES_H_

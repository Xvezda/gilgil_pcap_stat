#ifndef PCAP_STAT_IP_H_
#define PCAP_STAT_IP_H_

#include "pcap_stat_common.h"


class IPAddress {
public:
  IPAddress(uint32_t ip) {
    address = ip;
  }
  virtual ~IPAddress() {}

  const char* CStr() const {
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = address;
    return inet_ntoa(addr.sin_addr);
  }

  operator const char*() {
    return CStr();
  }

  bool operator<(const IPAddress& other) const {
    return address < other.address;
  }

  bool operator>(const IPAddress& other) const {
    return other.address < address;
  }

  bool operator==(const IPAddress& other) const {
    return !(address < other.address) && !(other.address < address);
  }

  bool operator!=(const IPAddress& other) const {
    return !(address == other.address);
  }
private:
  uint32_t address;
};



#endif  // PCAP_STAT_IP_H_

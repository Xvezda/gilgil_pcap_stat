// Copyright (C) 2020 Xvezda <https://xvezda.com/>
#ifndef PCAP_STAT_MAC_H_
#define PCAP_STAT_MAC_H_

#include "pcap_stat_common.h"


class MACAddress {
public:
  MACAddress(const u_char* raw_packet) {
    for (size_t i = 0; i < Size(); ++i) {
      mac_addr[i] = raw_packet[i];
    }
    mac_addr_buf[0] = '\0';
  }
  virtual ~MACAddress() {}

  static constexpr size_t Size() {
    return ARRLEN(mac_addr);
  }

  const char* CStr() const {
    char tmpbuf[ /* Hex */ 2 + /* Null character */ 1];

    for (size_t i = 0; i < Size(); ++i) {
      std::snprintf(tmpbuf, sizeof(tmpbuf), "%02x", mac_addr[i]);
      std::strncat(mac_addr_buf, tmpbuf, std::strlen(tmpbuf));
      if (i != Size() - 1) {
        std::strncat(mac_addr_buf, separator, std::strlen(separator));
      }
    }
    mac_addr_buf[sizeof(mac_addr_buf) - 1] = '\0';

    return mac_addr_buf;
  }

  bool operator<(const MACAddress& other) const {
    for (size_t i = 0; i < ARRLEN(mac_addr); ++i) {
      if (mac_addr[i] < other.mac_addr[i]) return true;
    }
    return false;
  }

  bool operator>(const MACAddress& other) const {
    return !(other < *this);
  }

  bool operator==(const MACAddress& other) const {
    return !(*this < other) && !(other < *this);
  }

  bool operator!=(const MACAddress& other) const {
    return !(*this == other);
  }

private:
  static constexpr char separator[] = ":";

  uint8_t         mac_addr[6];
  mutable char    mac_addr_buf[ /* Hex */        ARRLEN(mac_addr)*2 +
                                /* Separator */ (ARRLEN(mac_addr)-1) +
                                /* Null */ 1 ];
};
constexpr char MACAddress::separator[];


#endif  // PCAP_STAT_MAC_H_


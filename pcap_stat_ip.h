// Copyright (C) 2020 Xvezda <https://xvezda.com/>
#ifndef PCAP_STAT_IP_H_
#define PCAP_STAT_IP_H_

#include "pcap_stat_common.h"
#include "pcap_stat_int.h"


struct ip_header_s {
  unsigned version     : 4;
  unsigned header_len  : 4;
  unsigned tos         : 8;
  unsigned total       : 16;
  unsigned id          : 16;
  unsigned flag        : 3;
  unsigned frag_offset : 13;
  unsigned ttl         : 8;
  unsigned proto_id    : 8;
  unsigned checksum    : 16;
  unsigned sip         : 32;
  unsigned dip         : 32;
  unsigned option      : 24;
  unsigned padding     : 8;
};


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


class IPPacket : public PacketData {
public:
  using ip_header_t = struct ip_header_s;

  IPPacket(const u_char* raw_packet) {
    std::memcpy(&header, raw_packet, sizeof(header));
  }
  virtual ~IPPacket() {}

  const IPAddress GetSIP() const override {
    return IPAddress(header.sip);
  }

  const IPAddress GetDIP() const override {
    return IPAddress(header.dip);
  }

  size_t GetTotal() const override {
    return header.total;
  }

private:
  ip_header_t header;
};


#endif  // PCAP_STAT_IP_H_

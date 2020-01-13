#ifndef PCAP_STAT_H_
#define PCAP_STAT_H_

#include <iostream>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <unistd.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>


#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))


class PacketData {
public:
  PacketData() {}
  virtual ~PacketData() {}
};

struct arp_header_s {
  unsigned hw_type      : 16;
  unsigned proto_type   : 16;
  unsigned hw_len       : 8;
  unsigned proto_len    : 8;
  unsigned operation    : 16;
  unsigned s_hw_addr    : 32;
  unsigned s_proto_addr : 32;
  unsigned d_hw_addr    : 32;
  unsigned d_proto_addr : 32;
};

class ArpPacket : public PacketData {
public:
  using arp_header_t = struct arp_header_s;

  ArpPacket(const u_char *raw_packet) {
    std::memcpy(&header, raw_packet, sizeof(header));
  }
  virtual ~ArpPacket() {}
private:
  arp_header_t header;
};


class IpAddress {
public:
  IpAddress(uint32_t ip) {
    address = ip;
  }
  virtual ~IpAddress() {}

  const char* CStr() const {
    struct sockaddr_in addr;
    addr.sin_addr.s_addr = address;
    return inet_ntoa(addr.sin_addr);
  }

  operator const char*() {
    return CStr();
  }
private:
  uint32_t address;
#if 0
  char     ip_addr_buf[ /* 0 ~ 255 x 4 */ 3*4 +
                        /* Separator */   1*4 +
                        /* Null */        1 ];
#endif
};


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

class IpPacket : public PacketData {
public:
  using ip_header_t = struct ip_header_s;

  IpPacket(const u_char* raw_packet) {
    std::memcpy(&header, raw_packet, sizeof(header));
  }
  virtual ~IpPacket() {}

  const IpAddress GetSip() {
    return IpAddress(header.sip);
  }

  const IpAddress GetDip() {
    return IpAddress(header.dip);
  }
private:
  ip_header_t header;
};

class EthType {
public:
  EthType(const u_char* raw_packet) {
    for (size_t i = 0; i < ARRLEN(type); ++i) {
      type[i] = raw_packet[i];
    }
  }
  virtual ~EthType() {}

  static constexpr size_t Size() {
    return ARRLEN(type);
  }

  const char* CStr() {
    if (type[0] == 0x08 && type[1] == 0x06) {
      return "ARP";
    } else {  // TODO: Add other protocols
      return "IPv4";
    }
  }

  operator u_char*() {
    return reinterpret_cast<u_char*>(type);
  }
private:
  uint8_t type[2];
};

class MacAddress {
public:
  MacAddress(const u_char* raw_packet) {
    for (size_t i = 0; i < Size(); ++i) {
      mac_addr[i] = raw_packet[i];
    }
    mac_addr_buf[0] = '\0';
  }
  virtual ~MacAddress() {}

  static constexpr size_t Size() {
    return ARRLEN(mac_addr);
  }

  const char* CStr() {
    char tmpbuf[ /* Hex */ 2 + /* Null character */ 1];

    for (size_t i = 0; i < Size(); ++i) {
      std::snprintf(tmpbuf, sizeof(tmpbuf), "%02x", mac_addr[i]);
      std::strncat(mac_addr_buf, tmpbuf, sizeof(mac_addr_buf));
      if (i != Size() - 1) {
        std::strncat(mac_addr_buf, separator, sizeof(mac_addr_buf));
      }
    }
    mac_addr_buf[sizeof(mac_addr_buf) - 1] = '\0';

    return mac_addr_buf;
  }

private:
  static constexpr char separator[] = ":";

  uint8_t mac_addr[6];
  char    mac_addr_buf[ARRLEN(mac_addr)*2 + (ARRLEN(mac_addr)-1) + 1];
};
constexpr char MacAddress::separator[];

class EthPacket {
public:
  EthPacket(const u_char* raw_packet)
      : dmac(raw_packet), smac(raw_packet + MacAddress::Size()),
        type(raw_packet + MacAddress::Size() * 2) {
    const u_char* data_ptr = raw_packet + MacAddress::Size() * 2 + \
                       EthType::Size();
    u_char* type_ptr = static_cast<u_char*>(type);

    if (type_ptr[0] == 0x08 && type_ptr[1] == 0x06) {
      data = new ArpPacket(data_ptr);
    } else {  // TODO: Add other protocols
      data = new IpPacket(data_ptr);
    }
  }

  virtual ~EthPacket() {
    if (data != nullptr) {
      delete data;
    }
  }

  void Show() {
    std::cout << "dmac:\t" << dmac.CStr() << std::endl;
    std::cout << "smac:\t" << smac.CStr() << std::endl;
    std::cout << "type:\t" << type.CStr() << std::endl;

    u_char* type_ptr = static_cast<u_char*>(type);
    // If type is IPv4
    if (type_ptr[0] == 0x08 && type_ptr[1] == 0x00) {
      std::cout << "sip: " << dynamic_cast<IpPacket*>(data)->GetSip().CStr()
                << std::endl;
      std::cout << "dip: " << dynamic_cast<IpPacket*>(data)->GetDip().CStr()
                << std::endl;
    }
  }

private:
  MacAddress  dmac;
  MacAddress  smac;
  EthType     type;
  PacketData* data;
};


static char errbuf[PCAP_ERRBUF_SIZE];

class PcapWrapper {
public:
  PcapWrapper(const char* filename)
      : header(nullptr), raw_packet(nullptr) {
    handle = pcap_open_offline(filename, errbuf);
    // FIXME: std::system_error?
    if (handle == nullptr) throw std::runtime_error(errbuf);
  }

  const EthPacket Next() {
    int result = pcap_next_ex(handle, &header, &raw_packet);

    if (result != 1) throw std::runtime_error(errbuf);

    return EthPacket(raw_packet);
  }

  virtual ~PcapWrapper() {
    if (handle != nullptr) {
      pcap_close(handle);
    }
  }
private:
  pcap_t* handle;

  struct  pcap_pkthdr* header;
  const   u_char*      raw_packet;
};

#endif  // PCAP_STAT_H_

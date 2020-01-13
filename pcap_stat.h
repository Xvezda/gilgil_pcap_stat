#ifndef PCAP_STAT_H_
#define PCAP_STAT_H_

#include <iostream>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <pcap/pcap.h>


class EthType {
public:
  EthType(const u_char* raw_packet) {
    for (size_t i = 0; i < sizeof(type) / sizeof(uint8_t); ++i) {
      type[i] = raw_packet[i];
    }
  }
  virtual ~EthType() {}
private:
  uint8_t type[2];
};

class MacAddress {
public:
  MacAddress(const u_char* raw_packet) {
    for (size_t i = 0; i < Size(); ++i) {
      mac_address[i] = raw_packet[i];
    }
  }
  virtual ~MacAddress() {}

  static constexpr size_t Size() {
    return sizeof(mac_address) / sizeof(uint8_t);
  }

  const char* CStr() {
    char tmpbuf[ /* Hex */ 2 + /* Null character */ 1];

    for (size_t i = 0; i < Size(); ++i) {
      std::snprintf(tmpbuf, sizeof(tmpbuf), "%02x", mac_address[i]);
      std::strncat(mac_address_buf, tmpbuf, sizeof(mac_address_buf));
      if (i != Size() - 1) {
        std::strncat(mac_address_buf, separator, sizeof(mac_address_buf));
      }
    }
    return mac_address_buf;
  }

private:
  static constexpr char separator[] = ":";

  uint8_t mac_address[6];
  char    mac_address_buf[6*2 + (6-1)];
};
constexpr char MacAddress::separator[];

class EthPacket {
public:
  EthPacket(const u_char* raw_packet)
      : dmac(raw_packet), smac(raw_packet + MacAddress::Size()),
        type(raw_packet + MacAddress::Size() * 2) {}
  virtual ~EthPacket() {}

  void Show() {
    std::cout << "dmac:\t" << dmac.CStr() << std::endl;
    std::cout << "smac:\t" << smac.CStr() << std::endl;
  }
private:
  MacAddress dmac;
  MacAddress smac;
  EthType    type;
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

  EthPacket Next() {
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

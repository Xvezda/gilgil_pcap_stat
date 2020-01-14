#ifndef PCAP_STAT_ETH_H_
#define PCAP_STAT_ETH_H_


#include "pcap_stat_common.h"
#include "pcap_stat_int.h"
#include "pcap_stat_mac.h"
#include "pcap_stat_ip.h"
#include "pcap_stat_arp.h"

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


class EthPacket {
public:
  EthPacket(const u_char* raw_packet)
      : dmac(raw_packet), smac(raw_packet + MACAddress::Size()),
        type(raw_packet + MACAddress::Size() * 2) {
    const u_char* data_ptr = raw_packet + MACAddress::Size() * 2 +
                       EthType::Size();
    u_char* type_ptr = static_cast<u_char*>(type);

    if (type_ptr[0] == 0x08 && type_ptr[1] == 0x06) {
      data = new ArpPacket(data_ptr);
    } else {  // TODO: Add other protocols
      data = new IPPacket(data_ptr);
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
    std::cout << "sip:\t" << data->GetSIP().CStr()
              << std::endl;
    std::cout << "dip:\t" << data->GetDIP().CStr()
              << std::endl;
    std::cout << "total:\t" << data->GetTotal()
              << std::endl;
    std::cout << std::endl;
  }

  const MACAddress GetDMAC() const {
    return dmac;
  }

  const MACAddress GetSMAC() const {
    return smac;
  }

  const IPAddress GetSIP() const {
    return data->GetSIP();
  }

  const IPAddress GetDIP() const {
    return data->GetDIP();
  }

  const PacketData* GetPacketData() const {
    return data;
  }

  size_t GetTotal() const {
    return kEthSize + data->GetTotal();
  }

private:
  MACAddress  dmac;
  MACAddress  smac;
  EthType     type;
  PacketData* data;
};


#endif  // PCAP_STAT_ETH_H_

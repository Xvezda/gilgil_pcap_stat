#ifndef PCAP_STAT_H_
#define PCAP_STAT_H_

#include "pcap_stat_common.h"
#include "pcap_stat_mac.h"
#include "pcap_stat_ip.h"


typedef struct statistics_table_s {
  size_t packets;
  size_t bytes;
} statistics_t;


class PacketData {
public:
  PacketData() {}
  virtual ~PacketData() {}
  virtual const IPAddress GetSIP() const = 0;
  virtual const IPAddress GetDIP() const = 0;
  virtual size_t GetTotal() const = 0;
};

struct arp_header_s {
  unsigned hw_type      : 16;
  unsigned proto_type   : 16;
  unsigned hw_len       : 8;
  unsigned proto_len    : 8;
  unsigned operation    : 16;

  uint8_t  s_hw_addr[6];
  uint32_t s_proto_addr;
  uint8_t  d_hw_addr[6];
  uint32_t d_proto_addr;
} __attribute__((aligned(1), packed));

class ArpPacket : public PacketData {
public:
  using arp_header_t = struct arp_header_s;

  ArpPacket(const u_char *raw_packet) {
    std::memcpy(&header, raw_packet, sizeof(header));
  }
  virtual ~ArpPacket() {}

  const IPAddress GetSIP() const override {
    return IPAddress(header.s_proto_addr);
  }

  const IPAddress GetDIP() const override {
    return IPAddress(header.d_proto_addr);
  }

  size_t GetTotal() const override {
    return (/* HW type(16) + Proto type(16) */              32 / kByteBits +
            /* HW addr(8) + Proto addr(8) + opcode(16) */ + 32 / kByteBits +
            header.hw_len * 2 + header.proto_len * 2);
  }
private:
  arp_header_t header;
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

  void Statistic() {
    for (;;) {
      try {
        EthPacket eth = Next();

        /* End points */
        try {
          mac_eps[eth.GetDMAC()].packets += 1;
          mac_eps[eth.GetSMAC()].packets += 1;
          mac_eps[eth.GetDMAC()].bytes   += eth.GetTotal();
          mac_eps[eth.GetSMAC()].bytes   += eth.GetTotal();
          ip_eps[eth.GetDIP()].packets   += 1;
          ip_eps[eth.GetSIP()].packets   += 1;
          ip_eps[eth.GetDIP()].bytes     += eth.GetTotal();
          ip_eps[eth.GetSIP()].bytes     += eth.GetTotal();
        } catch (const std::out_of_range& e_) {
          mac_eps[eth.GetDMAC()].packets = 0;
          mac_eps[eth.GetSMAC()].packets = 0;
          mac_eps[eth.GetDMAC()].bytes   = 0;
          mac_eps[eth.GetSMAC()].bytes   = 0;
          ip_eps[eth.GetDIP()].packets   = 0;
          ip_eps[eth.GetSIP()].packets   = 0;
          ip_eps[eth.GetDIP()].bytes     = 0;
          ip_eps[eth.GetSIP()].bytes     = 0;
        }

        /* Conversations */
        try {
          mac_convs[std::make_pair(eth.GetDMAC(), eth.GetSMAC())].packets
            += 1;
          ip_convs[std::make_pair(eth.GetSIP(), eth.GetDIP())].packets
            += 1;
          mac_convs[std::make_pair(eth.GetDMAC(), eth.GetSMAC())].bytes
            += eth.GetTotal();
          ip_convs[std::make_pair(eth.GetSIP(), eth.GetDIP())].bytes
            += eth.GetTotal();
        } catch (const std::out_of_range& e_) {
          mac_convs[std::make_pair(eth.GetDMAC(), eth.GetSMAC())].packets
            = 0;
          ip_convs[std::make_pair(eth.GetSIP(), eth.GetDIP())].packets
            = 0;
          mac_convs[std::make_pair(eth.GetDMAC(), eth.GetSMAC())].bytes
            = 0;
          ip_convs[std::make_pair(eth.GetSIP(), eth.GetDIP())].bytes
            = 0;
        }
      } catch(const std::exception& e) {
        break;
      }
    }

    /* Eth end points */
    std::cout << std::string(20, '=') << " Endpoints "
              << std::string(20, '=') << std::endl;

    std::cout << std::setiosflags(std::ios::fixed)
              << std::setw(18) << std::setprecision(3) << std::left
              << "Address" << " | "
              << "Packets" << " | "
              << "Bytes" << std::endl;
    std::cout << std::string(79, '-') << std::endl;
    for (auto const& x : mac_eps) {
      std::cout << std::setiosflags(std::ios::fixed)
                << std::setw(18) << std::setprecision(3) << std::left
                << x.first.CStr() << " | "
                << x.second.packets << " | "
                << x.second.bytes << std::endl;
    }
    std::cout << std::endl;

    /* IP end points */
      std::cout << std::setiosflags(std::ios::fixed)
                << std::setw(18) << std::setprecision(3) << std::left
                << "Address" << " | "
                << "Packets" << " | "
                << "Bytes" << std::endl;
      std::cout << std::string(79, '-') << std::endl;
    for (auto const& x : ip_eps) {
      std::cout << std::setiosflags(std::ios::fixed)
                << std::setw(18) << std::setprecision(3) << std::left
                << x.first.CStr() << " | "
                << x.second.packets << " | "
                << x.second.bytes << std::endl;
    }
    std::cout << std::endl;

    /* Ethernet conversations */
    std::cout << std::string(20, '=') << " Conversations "
              << std::string(20, '=') << std::endl;

    std::cout << std::setiosflags(std::ios::fixed)
              << std::setw(18) << std::setprecision(3) << std::left
              << "Address A" << " | "
              << "Address B" << " | "
              << "Packets" << " | "
              << "Bytes" << std::endl;
    std::cout << std::string(79, '-') << std::endl;
    for (auto const& x : mac_convs) {
      std::cout << std::setiosflags(std::ios::fixed)
                << std::setw(18) << std::setprecision(3) << std::left
                << x.first.first.CStr() << " | "
                << x.first.second.CStr() << " | "
                << x.second.packets << " | "
                << x.second.bytes << std::endl;
    }
    std::cout << std::endl;

    /* IP conversations */
    std::cout << std::setiosflags(std::ios::fixed)
              << std::setw(18) << std::setprecision(3) << std::left
              << "Address A" << " | "
              << "Address B" << " | "
              << "Packets" << " | "
              << "Bytes" << std::endl;
    std::cout << std::string(79, '-') << std::endl;
    for (auto const& x : ip_convs) {
      std::cout << std::setiosflags(std::ios::fixed)
                << std::setw(18) << std::setprecision(3) << std::left
                << x.first.first.CStr() << " | "
                << x.first.second.CStr() << " | "
                << x.second.packets << " | "
                << x.second.bytes << std::endl;
    }
    std::cout << std::endl;
  }
private:
  /* End points */
  std::map<MACAddress, statistics_t> mac_eps;
  std::map<IPAddress, statistics_t> ip_eps;

  /* Conversations */
  std::map<std::pair<MACAddress, MACAddress>, statistics_t> mac_convs;
  std::map<std::pair<IPAddress, IPAddress>, statistics_t> ip_convs;

  pcap_t* handle;

  struct  pcap_pkthdr* header;
  const   u_char*      raw_packet;
};

#endif  // PCAP_STAT_H_

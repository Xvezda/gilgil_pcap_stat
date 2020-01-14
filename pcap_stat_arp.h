#ifndef PCAP_STAT_ARP_H_
#define PCAP_STAT_ARP_H_

#include "pcap_stat_common.h"
#include "pcap_stat_int.h"

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



#endif  // PCAP_STAT_ARP_H_

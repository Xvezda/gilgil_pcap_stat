#ifndef PCAP_STAT_INT_H_
#define PCAP_STAT_INT_H_


class IPAddress;

/* Interface */
class PacketData {
public:
  PacketData() {}
  virtual ~PacketData() {}
  virtual const IPAddress GetSIP() const = 0;
  virtual const IPAddress GetDIP() const = 0;
  virtual size_t GetTotal() const = 0;
};

#endif  // PCAP_STAT_INT_H_

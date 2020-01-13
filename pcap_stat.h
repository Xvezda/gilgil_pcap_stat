#ifndef PCAP_STAT_H_
#define PCAP_STAT_H_

#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include <pcap/pcap.h>


static char errbuf[PCAP_ERRBUF_SIZE];

class PcapWrapper {
public:
  PcapWrapper(const char* filename)
      : header(nullptr), raw_packet(nullptr) {
    handle = pcap_open_offline(filename, errbuf);
    // FIXME: std::system_error?
    if (handle == nullptr) throw std::runtime_error(errbuf);
  }

  int next() {
    int result = pcap_next_ex(handle, &header, &raw_packet);

    if (result != 1) return result;

    for (size_t i = 0; i < 20; ++i) {
      std::printf("%02X ", raw_packet[i]);
    }
    return result;
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

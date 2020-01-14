// Copyright (C) 2020 Xvezda <https://xvezda.com/>
#ifndef PCAP_STAT_H_
#define PCAP_STAT_H_

#include "pcap_stat_common.h"

#include "pcap_stat_eth.h"
#include "pcap_stat_mac.h"
#include "pcap_stat_ip.h"
#include "pcap_stat_arp.h"


typedef struct stat_table_s {
  size_t packets;
  size_t bytes;
} stat_t;

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
  std::map<MACAddress, stat_t> mac_eps;
  std::map<IPAddress, stat_t> ip_eps;

  /* Conversations */
  std::map<std::pair<MACAddress, MACAddress>, stat_t> mac_convs;
  std::map<std::pair<IPAddress, IPAddress>, stat_t> ip_convs;

  pcap_t* handle;

  struct  pcap_pkthdr* header;
  const   u_char*      raw_packet;
};

#endif  // PCAP_STAT_H_

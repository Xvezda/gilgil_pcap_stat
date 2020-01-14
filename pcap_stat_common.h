#ifndef PCAP_STAT_COMMON_H_
#define PCAP_STAT_COMMON_H_


#include <iostream>
#include <iomanip>
#include <utility>
#include <string>
#include <map>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <unistd.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>

#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

const auto kByteBits = 8;
const auto kEthSize  = 14;


#endif  // PCAP_STAT_COMMON_H_

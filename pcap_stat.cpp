// Copyright (C) 2020 Xvezda <https://xvezda.com/>
#include "pcap_stat.h"


int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " [pcapfile]" << std::endl;

    return EXIT_FAILURE;
  }
  const char* filename = argv[1];

  PcapWrapper wrapper(filename);
  wrapper.Statistic();

  return EXIT_SUCCESS;
}


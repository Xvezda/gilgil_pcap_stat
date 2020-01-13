#include "pcap_stat.h"

static char errbuf[PCAP_ERRBUF_SIZE];


int main(int argc, char **argv) {
  if (argc != 2) {
    std::cout << "usage: " << argv[0] << " [pcapfile]" << std::endl;

    return EXIT_FAILURE;
  }
  const char* filename = argv[1];
  pcap_t* handle = pcap_open_offline(filename, errbuf);

  return EXIT_SUCCESS;
}


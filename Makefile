CPP = g++
CPPFLAGS = -Wall -Wextra -pedantic -std=c++14
LDLIBS = -lpcap
SOURCE_FILES = $(wildcard *.cpp)
TARGET = pcap_stat


all: $(TARGET)

debug: CPPFLAGS += -DDEBUG -g -O0
debug: all

clean:
	rm -rf $(TARGET) *.o

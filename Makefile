CPP = g++
CPPFLAGS = -Wall -Wextra -pedantic
LDLIBS = -lpcap
SOURCE_FILES = $(wildcard *.cpp)
TARGET = pcap_stat


all: $(TARGET)

%.o: %.cpp

clean:
	rm -rf $(TARGET) *.o

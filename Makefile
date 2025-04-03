CXX=g++
CC=g++
CPPFLAGS=-Wall -Werror -O2

TARGET=twig
SRCS=${wildcard *.cc}
OBJECTS=${SRCS:.cc=.o}
HEADERS=${wildcard headers/*.h}

all: $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJECTS): $(HEADERS)


clean:
	cd udp_ping && make clean
	rm -f $(TARGET) *.o *.dmp socket_time twig /udp_ping

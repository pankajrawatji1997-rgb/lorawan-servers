CXX=g++
CXXFLAGS=-std=c++17 -O2 -Wall -Iinclude
LDFLAGS=-lssl -lcrypto -lcjson -lpthread

SRC=$(wildcard src/*.cpp)
OBJ=$(SRC:.cpp=.o)

all: network_server

network_server: $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f src/*.o network_server

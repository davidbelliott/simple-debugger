CC=gcc
CXX=g++
CCFLAGS=-Wall
LDFLAGS=-lreadline
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
LIBS=dwarf4/libdwarf4.a
TARGET=debugger

all: $(TARGET)

$(TARGET): $(OBJECTS) $(LIBS)
	$(CXX) -o $@ $^ $(LDFLAGS) 

%.o: %.c
	$(CC) $(CCFLAGS) -c $<

.PHONY: clean
clean:
	rm -f *.o $(TARGET)

.PHONY: dwarf4/libdwarf4.a
dwarf4/libdwarf4.a:
	cd dwarf4 && $(MAKE) MAKEFLAGS="libs"

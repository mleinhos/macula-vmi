CC = gcc
CFLAGS = -Wall #-std=c99
DFLAGS = -fsanitize=address
TARGET = vminspect

LDFLAGS += $(shell pkg-config --libs json-c)
LDFLAGS += $(shell pkg-config --libs libvmi)
LDFLAGS += $(shell pkg-config --libs xencontrol)
LDFLAGS += $(shell pkg-config --libs xenlight)
LDFLAGS += $(shell pkg-config --libs xenevtchn)

DEPS = vminspect.h profile.h symbol.h xen-access.h vmi.h
OBJ = vminspect.o profile.o xen-access.o vmi.o

.PHONY: clean

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS) $(DFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(DFLAGS) 

clean:
	rm *.o

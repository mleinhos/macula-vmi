_arch = $(shell uname -m)

CC = gcc

CFLAGS = -I../common -I.

#CFLAGS += -O3 -g
CFLAGS += -O0 -ggdb

TARGET = NInspector

# Common flags, etc
INC = -I../ext/clog
LIBS = -lvmi -lxenctrl -lxenlight -ljson-c -lzmq -lpthread

ifeq ($(_arch), aarch64)
# ARM64 definitions
CFLAGS += -DARM64
INC += -I/usr/include/glib-2.0/ -I/usr/lib/aarch64-linux-gnu/glib-2.0/include
LIBS +=  -lglib-2.0

else

# x86_64 definitions
CFLAGS += -DX86_64

INC += $(shell pkg-config --cflags glib-2.0)
LIBS += $(shell pkg-config --libs glib-2.0)

endif

DEPS = nif-vmi-iface.h nvmi-common.h nvmi-event-templates.h nvmi-internal-defs.h
OBJS = nvmi-main.o nif-vmi-iface.o ## process_kill_helper.o

.PHONY: clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)  $(INC)

clean:
	rm -f  $(TARGET) $(OBJS)

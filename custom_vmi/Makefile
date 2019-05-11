
_arch = $(shell uname -m)

CC = gcc

#CFLAGS = -O3
CFLAGS = -O0 -ggdb

TARGET = NInspector

ifeq ($(_arch), "aarch64")
# ARM64 definitions
INC = -I/usr/include/glib-2.0/ -I/usr/lib/aarch64-linux-gnu/glib-2.0/include/ -I..
LIBS = -lvmi -lxenctrl -lxenlight -lglib-2.0
LIBS = -lvmi -lxenctrl -lxenlight -lglib-2.0 -lzmq -pthread

else

# x86_64 definitions
INC = $(shell pkg-config --cflags glib-2.0)
LIBS = -lvmi -lxenctrl -lxenlight $(shell pkg-config --libs glib-2.0) -lzmq -lpthread

endif

DEPS = nvmi.h
OBJS = nvmi-main.o nif-vmi-iface.o process_kill_helper.o

.PHONY: clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)  $(INC)

clean:
	rm -f  $(TARGET) $(OBJS)

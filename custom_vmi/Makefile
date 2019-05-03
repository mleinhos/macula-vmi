
_arch = $(shell uname -m)

CC = gcc
CFLAGS = -O3
TARGET = NInspector

##ifeq ($(_arch), "x86_64")
ifeq ($(_arch), "aarch64")

# ARM64 definitions
INC = -I/usr/include/glib-2.0/ -I/usr/lib/aarch64-linux-gnu/glib-2.0/include/ -I..
LIBS = -lvmi -lxenctrl -lxenlight -lglib-2.0

else

# x86_64 definitions
INC = $(shell pkg-config --cflags glib-2.0)
LIBS = -lvmi -lxenctrl -lxenlight $(shell pkg-config --libflags glib-2.0)

endif


DEPS = nvmi.h
OBJS = nvmi.o nvmi-main.o nif-vmi-iface.o process_kill_helper.o

.PHONY: clean

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)  $(INC)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f  $(TARGET) $(OBJS)

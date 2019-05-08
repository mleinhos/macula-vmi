INC = -I/usr/include/glib-2.0/ -I/usr/lib/aarch64-linux-gnu/glib-2.0/include/ -I..
CC = gcc
CFLAGS = -O3
TARGET = NInspector

LIBS = -lvmi -lxenctrl -lxenlight -lglib-2.0 -lpthread -lzmq
DEPS = nvmi.h
OBJ = nvmi_arm.o ../process_kill_helper.o

.PHONY: clean

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LIBS) $(INC)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(INC)

clean:
	rm -f *.o $(TARGET)

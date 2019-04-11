#ifndef NVMI_H
#define NVMI_H

#include <libvmi/libvmi.h>

#define MAX_VCPUS 8
#define MAX_CALLS 400

typedef struct {
		uint8_t backup_byte;
		addr_t sys_addr;
		char name[128];
} sys_node;


#endif

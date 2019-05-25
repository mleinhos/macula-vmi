/**
 * Description: Defines common stuff for all of the VMI portion of the NVMIsystem.
 *
 * Company: Numen Inc.
 *
 * Developers: Matt Leinhos
 */

#ifndef NVMI_COMMON_DEFS_H
#define NVMI_COMMON_DEFS_H

#include "nvmi-public-defs.h"

// For clog
#define CLOGGER_ID  0

#define NVMI_MAX_SYSCALL_ARG_CT 6
#define NVMI_MAX_SYSCALL_CT 450

#define MAX_VCPUS 8
//#define MAX_SNAME_LEN 128
#define MAX_SNAME_LEN (SYSCALL_MAX_NAME_LEN)


#define PG_OFFSET_BITS 12
#define DOM_PAGE_SIZE (1 << PG_OFFSET_BITS)

#define MKADDR(frame, offset) (((frame) << PG_OFFSET_BITS) | offset)

					  
#ifndef NUMBER_OF
#   define NUMBER_OF(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef MIN
#    define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#    define MAX(x,y) ((x) < (y) ? (x) : (y))
#endif


typedef unsigned long atomic_t;

static inline atomic_t atomic_inc (atomic_t * val)
{
	return __sync_add_and_fetch (val, 1);
}

static inline atomic_t atomic_dec (atomic_t * val)
{
	return __sync_sub_and_fetch (val, 1);
}



#endif // NVMI_COMMON_DEFS_H
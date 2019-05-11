/**
 * Description: Provides templates for syscalls, so we know their arg count and types.
 *
 * Company: Numen Inc.
 *
 * Developers: Matt Leinhos
 */

#ifndef NVMI_SYSCALL_DEFS_H
#define NVMI_SYSCALL_DEFS_H

#define NVMI_DEFAULT_SOCKADDR_LEN 14

#include <stdint.h>
#include <stdbool.h>
#include "nvmi-common.h"

/**
 * The types of syscall arguments supported
 */
typedef enum _nvmi_arg_type {
	NVMI_ARG_TYPE_NONE = 0,
	NVMI_ARG_TYPE_SCALAR, // any long value that is not dereferenced, including pointers
	NVMI_ARG_TYPE_STR,    // char *
	NVMI_ARG_TYPE_WSTR,   // wchar *
	NVMI_ARG_TYPE_SA,     // sockaddr *, resolved
} nvmi_arg_type_t;


/**
 * Definition of a syscall argument
 */
typedef struct _nvmi_syscall_arg {
	//const char * name;
	nvmi_arg_type_t type;
} nvmi_syscall_arg_t;

typedef struct _nvmi_syscall_def {
	const char * name; // really,the suffix -- whatever's after sys_
	int argct;
	bool does_deref;
	bool enabled;
	void * rtinfo; // runtime info
	nvmi_syscall_arg_t args [NVMI_MAX_SYSCALL_ARG_CT];
} nvmi_syscall_def_t;


static nvmi_syscall_def_t
nvmi_syscalls[] =
{
	{ .name = "open", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_STR    },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .name = "openat", .argct = 4, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_STR    },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .name = "read", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    {.type = NVMI_ARG_TYPE_SCALAR  },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .name = "write", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR} } },

	{ .name = "close", .argct = 1, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR }} },

	{ .name = "bind", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SA     } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .name = "connect", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SA     } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

};



#endif // NVMI_SYSCALL_DEFS_H

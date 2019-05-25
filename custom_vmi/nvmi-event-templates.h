/**
 * Description: Provides templates for syscalls, so we know their arg count and types.
 *
 * Company: Numen Inc.
 *
 * Developers: Matt Leinhos
 */

#ifndef NVMI_EVENT_TEMPLATES_H
#define NVMI_EVENT_TEMPLATES_H

//#define NVMI_MAX_SYSCALL_NAME_LEN 32

#include <stdint.h>
#include <stdbool.h>
#include "nvmi-common.h"


typedef enum _nvmi_callback_type {
	NVMI_CALLBACK_NONE = 0,
	NVMI_CALLBACK_SYSCALL,
	NVMI_CALLBACK_SPECIAL,
} nvmi_callback_type_t;


/**
 * The types of syscall arguments supported
 */
typedef enum _nvmi_arg_type {
	NVMI_ARG_TYPE_NONE = 0,
	NVMI_ARG_TYPE_SCALAR, // any long value that is not dereferenced, but NOT pointers
	NVMI_ARG_TYPE_PVOID,  // a pointer that we will NOT dereference
	NVMI_ARG_TYPE_STR,    // char *
	NVMI_ARG_TYPE_WSTR,   // wchar *
	NVMI_ARG_TYPE_SA,     // sockaddr *, resolved
	NVMI_ARG_TYPE_FDSET, // fd_set *, resolved ?
} nvmi_arg_type_t;


/**
 * Definition of a syscall argument
 */
typedef struct _nvmi_syscall_arg {
	enum syscall_arg_type type;
} nvmi_syscall_arg_t;

typedef struct _nvmi_cb_info {
	nvmi_callback_type_t cb_type;
	char name[SYSCALL_MAX_NAME_LEN];

	// syscall specific
	int argct;
	bool does_deref;
	bool enabled;
	void * rtinfo; // runtime info
	nvmi_syscall_arg_t args [NVMI_MAX_SYSCALL_ARG_CT];
} nvmi_cb_info_t;


static nvmi_cb_info_t
nvmi_syscalls [NVMI_MAX_SYSCALL_CT] =
{
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_open", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_STR    },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_openat", .argct = 4, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_STR    },
		    { .type = NVMI_ARG_TYPE_SCALAR },     // flags
		    { .type = NVMI_ARG_TYPE_SCALAR } } }, // mode (opt)

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_stat", .argct = 2, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_STR   },
		    { .type = NVMI_ARG_TYPE_PVOID } } },
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_fstat", .argct = 2, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_lstat", .argct = 2, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_STR },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_poll", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR  },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_select", .argct = 5, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  }, // fd_set *
		    { .type = NVMI_ARG_TYPE_PVOID  }, // fd_set *
		    { .type = NVMI_ARG_TYPE_PVOID  }, // fd_set *
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_inotify_add_watch", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID    }, // STR - but doesn't resolve
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_inotify_rm_watch", .argct = 2, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_read", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR  },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },


	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_write", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR} } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_close", .argct = 1, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR }} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_bind", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SA     } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_connect", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SA     } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_gettimeofday", .argct = 2, false, false, NULL,  // verbose
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_mmap", .argct = 6, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_munmap", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_lseek", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_chown", .argct = 3, true, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_STR },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_getuid",  .argct = 0, false, true, NULL, .args = {} },
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_geteuid", .argct = 0, false, true, NULL, .args = {} },
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_getpid",  .argct = 0, false, true, NULL, .args = {} },
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_getpgrp", .argct = 0, false, true, NULL, .args = {} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_wait4", .argct = 3, false, false, NULL, // very verbose!
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_clock_gettime", .argct = 2, false, false, NULL, // fairly verbose!
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_rt_sigaction", .argct = 3, false, true, NULL,
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	// !!!!!!!!!! INCOMPLETE/INCORRECT DEFS 
	// While incorrect, keep argct == 0
	// !!!!!!!!!!!!!!!!!!!!!!!!!!
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_futex", .argct = 0, false, true, NULL, .args = {} },

};

#endif // NVMI_EVENT_TEMPLATES_H

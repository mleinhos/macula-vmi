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
 * The types of syscall arguments supported. Compare with strace(1)
 * for inspiration on future types.
 */
typedef enum _nvmi_arg_type {
	NVMI_ARG_TYPE_NONE = 0,
	NVMI_ARG_TYPE_SCALAR, // any long value that is not dereferenced, but NOT pointers
	NVMI_ARG_TYPE_PVOID,  // a pointer that we will NOT dereference
	NVMI_ARG_TYPE_STR,    // char *
	NVMI_ARG_TYPE_WSTR,   // wchar *
	NVMI_ARG_TYPE_SA,     // sockaddr *, resolved
	NVMI_ARG_TYPE_FDSET,  // fd_set *, resolved ?
} nvmi_arg_type_t;


/**
 * Definition of a syscall argument
 */
typedef struct _nvmi_syscall_arg {
	enum syscall_arg_type type;
} nvmi_syscall_arg_t;


/**
 * Metadata about an event: its arguments, attributes, etc. This is
 * geared toward syscalls but is intended for all kernel events
 * (breakpoints) we care about.
 */
typedef struct _nvmi_cb_info {
	nvmi_callback_type_t cb_type;
	char name[SYSCALL_MAX_NAME_LEN];

	// How many times has this been hit?
	atomic_t hitct;

	// (Immutable) attributes and (mutable) state of the callback, intermingled here
	struct {
		unsigned long derefs    : 1; // dereferences guest memory
		unsigned long sticky    : 1; // cannot be disabled
		unsigned long enabled   : 1; // is currently enabled
		unsigned long reset_ctx : 1; // triggers reset in process context, e.g. sys_exec* family
	} state;

	// Syscall-specific stuff
	int argct;
	nvmi_syscall_arg_t args [NVMI_MAX_SYSCALL_ARG_CT];

} nvmi_cb_info_t;


static nvmi_cb_info_t
nvmi_syscalls [NVMI_MAX_SYSCALL_CT] =
{
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_open", .argct = 3,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_STR    },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_openat", .argct = 4,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_STR    },
		    { .type = NVMI_ARG_TYPE_SCALAR },     // flags
		    { .type = NVMI_ARG_TYPE_SCALAR } } }, // mode (opt)

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_stat", .argct = 2,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_STR   },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_fstat", .argct = 2,
	  .state = {  .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_lstat", .argct = 2,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_STR },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_poll", .argct = 3,
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR  },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_ppoll", .argct = 4,
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_select", .argct = 5,
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  }, // fd_set *
		    { .type = NVMI_ARG_TYPE_PVOID  }, // fd_set *
		    { .type = NVMI_ARG_TYPE_PVOID  }, // fd_set *
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_inotify_add_watch", .argct = 3,//, true, true,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID    }, // STR - but doesn't resolve
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_inotify_rm_watch", .argct = 2,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_read", .argct = 3,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	// Network stuff
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_bind", .argct = 3,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SA     } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_connect", .argct = 3,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SA     } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_setsockopt", .argct = 5,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_getsockopt", .argct = 5,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_send", .argct = 5,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_sendmsg", .argct = 6,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_SCALAR  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_recv", .argct = 5,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_recvmsg", .argct = 6,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_SCALAR  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_write", .argct = 3,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR} } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_close", .argct = 1,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR }} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_gettimeofday", .argct = 2, // verbose
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_PVOID } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_mmap", .argct = 6,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_munmap", .argct = 3,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_lseek", .argct = 3,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_chown", .argct = 3,
	  .state = { .derefs = 1, .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_STR },
		    { .type = NVMI_ARG_TYPE_SCALAR } ,
		    { .type = NVMI_ARG_TYPE_SCALAR } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_execve", .argct = 3,
	  .state = { .derefs = 1, .enabled = 1, .reset_ctx = 1},
	  .args = { { .type = NVMI_ARG_TYPE_STR },       // filename
		    { .type = NVMI_ARG_TYPE_PVOID } ,    // char * argv[]
		    { .type = NVMI_ARG_TYPE_PVOID } } }, // char * envp[]

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_getuid", .argct = 0,
	  .state = { .enabled = 1} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_geteuid", .argct = 0,
	  .state = { .enabled = 1} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL, // VERBOSE
	  .name = "sys_getpid",  .argct = 0,
	  .state = { .enabled = 0} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_getpgrp", .argct = 0,
	  .state = { .enabled = 1} },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_wait4", .argct = 3, // VERY VERBOSE!
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_PVOID },
		    { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_clock_gettime", .argct = 2, // FAIRLY VERBOSE!
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_rt_sigaction", .argct = 3,
	  .state = { .enabled = 1},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	{ .cb_type = NVMI_CALLBACK_SYSCALL, // VERBOSE, LITTLE VALUE?
	  .name = "sys_sigprocmask", .argct = 3,
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },
	{ .cb_type = NVMI_CALLBACK_SYSCALL,
	  .name = "sys_rt_sigprocmask", .argct = 3,
	  .state = { .enabled = 0},
	  .args = { { .type = NVMI_ARG_TYPE_SCALAR },
		    { .type = NVMI_ARG_TYPE_PVOID  },
		    { .type = NVMI_ARG_TYPE_PVOID  } } },

	// !!!!!!!!!! INCOMPLETE/INCORRECT DEF(S)
	// While incorrect, keep argct == 0
	// !!!!!!!!!!!!!!!!!!!!!!!!!!
	{ .cb_type = NVMI_CALLBACK_SYSCALL, // VERBOSE, INSIGNIFICANT
	  .name = "sys_futex", .argct = 0,
	  .state = { .enabled = 0} },

};

#endif // NVMI_EVENT_TEMPLATES_H

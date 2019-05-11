/**
 * Description: Defines support structures for tracking NVMI context and events.
 *
 * Company: Numen Inc.
 *
 * Developers: Matt Leinhos
 */

#ifndef NVMI_INTERNAL_DEFS_H
#define NVMI_INTERNAL_DEFS_H

#include <glib.h>
#include <libvmi/libvmi.h>
#include "nvmi-common.h"

#define NVMI_MAX_TASK_NAME_LEN 32

/**
 * This is the maximal set of registers we need to capture upon an event.
 */
typedef struct _nvmi_registers {

	union {
		struct {
			reg_t cr3;
			reg_t  sp;
			reg_t  gs;
		} intel;
		/*
		  reg_t  ax; // ?
		  reg_t  di;
		  reg_t  si;
		  reg_t  dx;
		  reg_t  r10;
		  reg_t  r8;
		  reg_t  r9;;
		  } intel;
		*/
		struct {
			reg_t ttbr0;
			reg_t ttbr1;
			reg_t sp_el0;
			reg_t  sp;
		} arm64;
		/*
		  reg_t  x0;
		  reg_t  x1;
		  reg_t  x2;
		  reg_t  x3;
		  reg_t  x4;
		  } arm64;
		*/	
	} arch;

	reg_t syscall_args[NVMI_MAX_SYSCALL_ARG_CT];
} nvmi_registers_t;


#if defined(ARM64)
static int nvmi_syscall_arg_regs[] = { X0, X1, X2, X3, X4, X5 };
#else
static int nvmi_syscall_arg_regs[] = { RDI, RSI, RDX, R10, R8, R9 };
#endif


typedef struct _nvmi_task_info {
	addr_t p_task_struct; // addr of task_struct
	addr_t kstack; // base of kernel stack
	vmi_pid_t pid;
	vmi_pid_t ppid;
	// how many live events reference this task info?
	unsigned long refct;
	char comm [NVMI_MAX_TASK_NAME_LEN];
} nvmi_task_info_t;


typedef struct _nvmi_event_context {
	nvmi_registers_t r;
	nvmi_task_info_t * task;
} nvmi_event_context_t;

#endif // NVMI_INTERNAL_DEFS_H

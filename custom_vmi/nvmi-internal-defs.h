/**
 * Description: Defines support structures for tracking NVMI context and events.
 *
 * Company: Numen Inc.
 *
 * Developers: Matt Leinhos
 */

#ifndef NVMI_INTERNAL_DEFS_H
#define NVMI_INTERNAL_DEFS_H

#define NVMI_MAX_ARG_MEM 512

#include <glib.h>
#include <libvmi/libvmi.h>
#include "nvmi-public-defs.h"
#include "nvmi-common.h"


/**
 * This is the maximal set of registers we need to capture upon every event.
 */
typedef struct _nvmi_registers {
	union {
		struct {
			reg_t cr3; // needed?
			reg_t  sp;
			reg_t  gs_base;
		} intel;
		struct {
			reg_t ttbr0;
			reg_t ttbr1;
			reg_t sp_el0;
			reg_t  sp; // needed?
		} arm64;
	} arch;

	reg_t syscall_args[NVMI_MAX_SYSCALL_ARG_CT];
} nvmi_registers_t;


#if defined(ARM64)
static int nvmi_syscall_arg_regs[] = { X0, X1, X2, X3, X4, X5 };
#else
static int nvmi_syscall_arg_regs[] = { RDI, RSI, RDX, R10, R8, R9 };
#endif


typedef struct _nvmi_task_info {
	addr_t kstack; // base of kernel stack
	addr_t  task_dtb;

	union {
		reg_t key; // the key used to put this into hash table
		addr_t p_task_struct; // addr of task_struct
	};

	unsigned long refct;
	
	// How many live events reference this task info? Destroyed when 0.
	process_creation_event_t einfo;
//	vmi_pid_t pid;
//	vmi_pid_t ppid;
//	char comm [PROCESS_MAX_COMM_NAME];

	// TODO: get full path to binary via task->mm->??, since it's a file-backed mmap()
	
} nvmi_task_info_t;

// TODO: exapnd for other event types
typedef struct _nvmi_event {
	nvmi_registers_t r;
	//nvmi_syscall_def_t * sc;

	// metadata about the event
	nvmi_cb_info_t * cbi;
	nvmi_task_info_t * task;

	// If we must collect process memory during the first callback...

	// ... track its offsets into "mem" field here
	int mem_ofs[NVMI_MAX_SYSCALL_ARG_CT];
	int arg_lens[NVMI_MAX_SYSCALL_ARG_CT];
	
	// ...and put it here
	uint8_t mem[NVMI_MAX_ARG_MEM];
} nvmi_event_t;

#endif // NVMI_INTERNAL_DEFS_H

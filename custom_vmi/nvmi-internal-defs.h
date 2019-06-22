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
typedef struct _nvmi_registers
{
	union {
		struct {
			arm_registers_t r;
			reg_t sp_el0;
			reg_t sp;
		} arm;

		struct {
			x86_registers_t r;
			reg_t sp;
		} x86;
	};
	reg_t syscall_args[NVMI_MAX_SYSCALL_ARG_CT];
} nvmi_registers_t;


#if defined(ARM64)
static int nvmi_syscall_arg_regs[] = { X0, X1, X2, X3, X4, X5 };
#else
static int nvmi_syscall_arg_regs[] = { RDI, RSI, RDX, R10, R8, R9 };
#endif


/**
 * Here's all the data we collect on a process context.
 */
typedef struct _nvmi_task_info
{
	addr_t     kstack;      // base of kernel stack
	addr_t     task_dtb;

	addr_t     key;         // the key used to put this into hash table
	addr_t     task_struct; // addr of task_struct

	uint64_t   uid;
	uint64_t   gid;
	vmi_pid_t  pid;
	char       comm[PROCESS_MAX_COMM_NAME];
	char       path[PROCESS_MAX_PATH];

	// How many live events reference this task info? Destroyed when 0.
	unsigned long refct;

	// TODO: get full path to binary via task->mm->??, since it's a file-backed mmap()

	// If not 0, this is the request ID that asked for the death of this process
	uint64_t   pending_kill_request_id;
	unsigned long kill_attempts;
} nvmi_task_info_t;


// TODO: exapnd for other event types
typedef struct _nvmi_event
{
	nvmi_registers_t r;

	// metadata about the event
	nvmi_cb_info_t * cbi;

	// task context of the event
	nvmi_task_info_t * task;

	// If we must collect process memory during the first callback...

	// ... track its offsets into "mem" field here
	int mem_ofs[NVMI_MAX_SYSCALL_ARG_CT];
	int arg_lens[NVMI_MAX_SYSCALL_ARG_CT];

	// ...and put it here
	uint8_t mem[NVMI_MAX_ARG_MEM];
} nvmi_event_t;

#endif // NVMI_INTERNAL_DEFS_H

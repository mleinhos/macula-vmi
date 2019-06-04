/**
 * Description: Main driver for Ninspector. Uses libvmi, rekall, and
 *              nvmi-iface
 *
 * Company: Numen Inc.
 *
 * Developers: Ali Islam
 *             Matt Leinhos
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libxl_utils.h>
#include <libxl.h>
#include <setjmp.h>
#include <xenctrl.h>
#include <libvmi/slat.h>
#include <xenevtchn.h>
#include <xen/vm_event.h>
#include <xenctrl_compat.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <zmq.h>

#define CLOG_MAIN 1
#include "clog.h"

#include "nif-vmi-iface.h"
#include "nvmi-event-templates.h"
#include "process_kill_helper.h"
#include "nvmi-internal-defs.h"


/*
 * Stopgap measure while we're working on reading userspace memory
 * contents. Do NOT define this in master until that capability
 * works!!!
 */

//#define EXPERIMENTAL_ARM_FEATURES 1

#define NVMI_LOG_FILE "/tmp/ninspector.log"

#define NVMI_EVENT_QUEUE_TIMEOUT_uS (5 * 1000)

//#define NVMI_KSTACK_MASK (~0xfff)  // 1 pg stack
//#define NVMI_KSTACK_MASK (~0x1fff) // 2 pg stack
#define NVMI_KSTACK_MASK (~0x3fff) // 4 pg stack

#define ZMQ_EVENT_CHANNEL "tcp://*:5555"
#define ZMQ_REQUEST_CHANNEL "tcp://localhost:5556"

#define KILL_PID_NONE ((vmi_pid_t)-1)

//
// Special instrumentation points
//
static nvmi_cb_info_t
nvmi_special_cbs[] =
{
#define NVMI_DO_EXIT_IDX 0
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "do_exit" },
#define NVMI_FD_INSTALL_IDX 1
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "fd_install" },
};


//
// Remaining TODO:
//
// - manage lifetime of process context
// - offload as much work as possible to consumer thread or to a post callback (notification of second VMI event)
//

typedef struct _nvmi_state {
	vmi_pid_t killpid;

	int act_calls;

	// Signal handler
	struct sigaction act;
	bool interrupted;
	volatile bool nif_busy;

	// VMI info
	addr_t task_name_ofs;
	addr_t task_pid_ofs;
	addr_t task_ppid_ofs;
	addr_t task_mm_ofs;
	addr_t mm_pgd_ofs;

	addr_t va_current_task;

	// Special-case breakpoints
	addr_t va_exit_mm;

	bool use_comms;
	void* zmq_context;
	void* zmq_event_socket;
	void* zmq_request_socket;

	// Maps easy value to process context, e.g. curent
	// task_struct, or base kernel stack pointer.
	GHashTable * context_lookup;

	GThread * consumer_thread;
	GAsyncQueue * event_queue;

	// Handles inboudn requests over ZMQ
	GThread * request_service_thread;

} nvmi_state_t;

static nvmi_state_t gstate = {0};


static void
logger_fini (void)
{
	clog_free (CLOGGER_ID);
}


static int
logger_init (const char * logfile,
	     int verbosity_level)
{
	int rc = 0;

	if (logfile) {
		fprintf (stderr, "Initializing logging to %s, verbosity=%d\n",
			 logfile, verbosity_level);
		rc =  clog_init_path (CLOGGER_ID, logfile);
	} else {
		fprintf (stderr, "Initializing logging to stderr, verbosity=%d\n",
			 verbosity_level);
		rc = clog_init_fd (CLOGGER_ID, fileno(stderr));		
	}
	if (rc) {
		fprintf (stderr, "Logger initialization failure\n");
		goto exit;
	}

	switch (verbosity_level) {
	case 0:
		(void) clog_set_level (CLOGGER_ID, CLOG_WARN);
		break;
	case 1:
		(void) clog_set_level (CLOGGER_ID, CLOG_INFO);
		break;
	default: // 2+
		(void) clog_set_level (CLOGGER_ID, CLOG_DEBUG);
		break;
	}

	// Minimize the clutter
	(void) clog_set_time_fmt (CLOGGER_ID, "");
	(void) clog_set_date_fmt (CLOGGER_ID, "");

exit:
	return rc;
}


static void
close_handler(int sig)
{
	clog_info (CLOG(CLOGGER_ID), "Received signal %d, shutting down", sig);
	if (!gstate.interrupted) {
		gstate.interrupted = true;
		nif_stop();
	}
}


static int
cb_gather_registers (vmi_instance_t vmi,
		     vmi_event_t* event,
		     nvmi_registers_t * regs,
		     int argct)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	reg_t x[8];

	for (int i = 0; i < argct; ++i) {
		status_t status = vmi_get_vcpureg (vmi,
						   &regs->syscall_args[i],
						   nvmi_syscall_arg_regs[i],
						   event->vcpu_id);
		if (VMI_FAILURE == status) {
			rc = EIO;
			goto exit;
		}
		//clog_debug (CLOG(CLOGGER_ID), "syscall arg %d = %lx", i, regs->syscall_args[i]);
	}

	// Get the rest of the context too, for context lookup. Beware KPTI!!
#if defined(ARM64)
	regs->arm.r = *(event->arm_regs);
	status  = vmi_get_vcpureg (vmi, &regs->arm.sp, SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.sp_el0, SP_EL0, event->vcpu_id);
#else
	regs->x86.r = *(event->x86_regs);
	status = vmi_get_vcpureg (vmi, &regs->x86.sp, RSP, event->vcpu_id);
#endif
	if (VMI_SUCCESS != status) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "vmi_get_vcpureg() failed");
		goto exit;
	}

/*
#if defined(ARM64)
	status  = vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr0,  TTBR0,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr1,  TTBR1,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp,     SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp_el0, SP_EL0, event->vcpu_id);

	for (int i = 0; i < NUMBER_OF(x); ++i) {
		(void) vmi_get_vcpureg (vmi, &x[i], R0+i, event->vcpu_id);
		clog_debug (CLOG(CLOGGER_ID), "R%d = 0x%lx", i, x[i]);
	}

	clog_debug (CLOG(CLOGGER_ID), "Event: ttbr0 = 0x%lx", event->arm_regs->ttbr0);
	clog_debug (CLOG(CLOGGER_ID), "Event: ttbr1 = 0x%lx", event->arm_regs->ttbr1);
	clog_debug (CLOG(CLOGGER_ID), "Event: ttbcr = 0x%lx", event->arm_regs->ttbcr);
	clog_debug (CLOG(CLOGGER_ID), "Event: cpsr  = 0x%lx", event->arm_regs->cpsr);

	clog_debug (CLOG(CLOGGER_ID), "context: ttbr0   = %lx", regs->arch.arm64.ttbr0);
	clog_debug (CLOG(CLOGGER_ID), "context: ttbr1   = %lx", regs->arch.arm64.ttbr1);
	clog_debug (CLOG(CLOGGER_ID), "context: sp_el0  = %lx", regs->arch.arm64.sp_el0);
	clog_debug (CLOG(CLOGGER_ID), "context: sp      = %lx", regs->arch.arm64.sp);

#else
	status  = vmi_get_vcpureg (vmi, &regs->arch.intel.cr3,     CR3,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.intel.sp,      RSP,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.intel.gs_base, GS_BASE, event->vcpu_id);
#endif
	if (VMI_SUCCESS != status) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "vmi_get_vcpureg() failed");
		goto exit;
	}
*/
exit:
	return rc;
}


/**
 * Destroy the task context when its ref count reaches 0. FIXME!
 */
static void
deref_task_context (gpointer arg)
{
	nvmi_task_info_t * tinfo = (nvmi_task_info_t *) arg;
	atomic_t val = 	atomic_dec (&tinfo->refct);
	assert (val >= 0);

	if (0 == val) {
		clog_info (CLOG(CLOGGER_ID), "**** Process pid=%ld comm=%s destroyed ****",
			 tinfo->pid, tinfo->comm);
		g_slice_free (nvmi_task_info_t, tinfo);
	}
}


static void
free_task_context (nvmi_task_info_t * tinfo)
{
	g_slice_free (nvmi_task_info_t, tinfo);
}


static int
cb_current_pid  (vmi_instance_t vmi,
		 vmi_event_t * vmievent,
		 nvmi_registers_t * regs,
		 addr_t * curr,
		 vmi_pid_t * pid)
{
	int rc = 0;
//	addr_t curr = 0;
	status_t status = VMI_SUCCESS;
	addr_t local_curr = 0;
	vmi_pid_t local_pid = 0;

#if defined(ARM64)
	// Fast: get current task_struct *

	// TODO: it's not clear that this works - we're seeing that
	// SP_EL0 has the same value across different contexts!
	local_curr = (addr_t) regs->arm.sp_el0;
#else
	// gs --> 64 bit, fs --> 32 bit
	status = vmi_read_addr_va(vmi,
				  regs->x86.r.gs_base + gstate.va_current_task,
				  0,
				  &local_curr);
	if (VMI_SUCCESS != status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to determine current task (from gs_base + curr_task_offset)");
		goto exit;
	}
#endif

	// Get current->pid
	status = vmi_read_32_va(vmi, local_curr + gstate.task_pid_ofs, 0, &local_pid);
	if (VMI_FAILURE == status) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's pid at %" PRIx64 " + %lx",
			   local_curr, gstate.task_pid_ofs);
		goto exit;
	}

exit:
	*curr = local_curr;
	*pid = local_pid;
	return rc;
}


	
static int
cb_current_task (vmi_instance_t vmi,
		  vmi_event_t * vmievent,
		  nvmi_registers_t * regs,
		  addr_t * task)
{
	int rc = 0;

#if defined(ARM64)
	// Fast: get current task_struct *

	// TODO: it's not clear that this works - we're seeing that
	// SP_EL0 has the same value across different contexts!
	*task = regs->arm.sp_el0;

#if 0
	// Get current->pid
	status = vmi_read_32_va(vmi,
				curr_task + gstate.task_pid_ofs,
				0,
				&(*tinfo)->pid);
	if (VMI_FAILURE == status) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's pid at %" PRIx64 " + %lx",
			 (*tinfo)->task_struct, gstate.task_pid_ofs);
		goto exit;
	}
#endif

	
#else
	// x86: slow
	// key = regs->arch.intel.sp & NVMI_KSTACK_MASK;
	// ^^^ too uncertain for a process identification ...
	status_t status = vmi_read_addr_va(vmi,
					   regs->x86.r.gs_base + gstate.va_current_task,
					   0,
					   task);
	if (VMI_SUCCESS != status) {
		rc = EIO;
		task = NULL;
		clog_warn (CLOG(CLOGGER_ID), "Failed to determine current task (from gs_base + curr_task_offset)");
		goto exit;
	}
#endif

exit:
	return rc;
}


static int
cb_build_task_context (vmi_instance_t vmi,
		       nvmi_registers_t * regs,
		       addr_t curr_task,
		       vmi_pid_t pid,
		       nvmi_task_info_t ** tinfo)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	char * pname = NULL;
	addr_t task_mm = 0;
	addr_t mm_pgd = 0;

	*tinfo = g_slice_new0 (nvmi_task_info_t);

	// TODO: context lifetime is mismanaged -- fix it.
	atomic_inc (&(*tinfo)->refct);

	// Figure out the currect task. See kernel's impl of current() for clues.
#if defined(ARM64)
	(*tinfo)->kstack = regs->arm.sp & NVMI_KSTACK_MASK;
#else
	(*tinfo)->kstack = regs->x86.sp & NVMI_KSTACK_MASK;
#endif
	(*tinfo)->task_struct = curr_task;

#if 0
	// Get current->pid
	status = vmi_read_32_va(vmi,
				curr_task + gstate.task_pid_ofs,
				0,
				&(*tinfo)->pid);
	if (VMI_FAILURE == status) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's pid at %" PRIx64 " + %lx",
			 (*tinfo)->task_struct, gstate.task_pid_ofs);
		goto exit;
	}
#endif

	(*tinfo)->pid = pid;

	// Get current->comm
	// TODO: This is wrong
	pname = vmi_read_str_va (vmi, curr_task + gstate.task_name_ofs, 0);
	if (NULL == pname) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's comm at %" PRIx64 " + %lx",
			 (*tinfo)->task_struct, gstate.task_name_ofs);
		goto exit;
	}

	clog_info (CLOG(CLOGGER_ID), "pid %d --> task %p, comm %s", pid, curr_task, pname);
	
	strncpy ((*tinfo)->comm, pname, sizeof((*tinfo)->comm));
	free (pname);

	// Get the process' tdb one way or another. We can't yet do this on ARM.
#if 0
	// Yes, these things are either wrong or cause an infinite loop on ARM

	// Read current->mm
	status = vmi_read_addr_va (vmi, curr_task + gstate.task_mm_ofs, 0, &task_mm);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read current->mm");
		goto exit;
	}

	// Read current->mm->pgd: Yields wrong result on ARM
	status = vmi_read_addr_va (vmi, task_mm + gstate.mm_pgd_ofs, 0, &(*tinfo)->task_dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read mm->pgd");
		goto exit;
	}

	clog_debug (CLOG(CLOGGER_ID), "(task->mm->pgd: PID %d --> dtb %lx",
		 (uint32_t) (*tinfo)->pid,
		 (*tinfo)->task_dtb);
#endif

#if defined(X86_64) || defined(EXPERIMENTAL_ARM_FEATURES)
	// Yes, these things are either wrong or cause an infinite loop on ARM

	status = vmi_pid_to_dtb (vmi, (*tinfo)->pid, &(*tinfo)->task_dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to find page base for task, pid=%ld",
			 (*tinfo)->pid);
		goto exit;
	}
	clog_debug (CLOG(CLOGGER_ID), "vmi_pid_to_dtb: PID %d --> dtb %lx",
		 (uint32_t) (*tinfo)->pid,
		 (*tinfo)->task_dtb);
#endif
	clog_debug (CLOG(CLOGGER_ID), "Build context: task=%lx (key) pid=%d comm=%s",
		    curr_task, (*tinfo)->pid, (*tinfo)->comm);

exit:
	return rc;
}


/**
 * pre_gather_context()
 *
 * Gather system context on the initial callback for a syscall. This
 * is called from the event callback and executed while the vCPU is
 * paused -- so make it quick!
 */
static int
cb_gather_context (vmi_instance_t vmi,
		    vmi_event_t* vmievent,
		    nvmi_cb_info_t * cbi,
		    nvmi_event_t ** event)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	nvmi_task_info_t * task = NULL;
	nvmi_event_t * evt = (nvmi_event_t *) g_slice_new0 (nvmi_event_t);
	int argct = (NULL == cbi ? 0 : cbi->argct);
	addr_t curr = 0;
	vmi_pid_t pid = 0;

	rc = cb_gather_registers (vmi, vmievent, &evt->r, argct);
	if (rc) {
		goto exit;
	}

	rc = cb_current_pid (vmi, vmievent, &evt->r, &curr, &pid);
//	rc = cb_current_task (vmi, vmievent, &evt->r, &curr);
	if (rc) {
		clog_warn (CLOG(CLOGGER_ID), "Context could not be found");
		goto exit;
	}

	// Look for key in known contexts. If it isn't there, allocate
	// new nvmi_task_info_t and populate it.
	// TODO: enable caching by figuring out why it's broken on ARM (current != our key)
//	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)curr);
	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)(unsigned long)pid);

	if (task && task->pid != pid) asm("int $3");

	clog_info (CLOG(CLOGGER_ID), "pid %d --> task %p", pid, task);
	
	if (NULL == task) {
		// build new context
		rc = cb_build_task_context (vmi, &evt->r, curr, pid, &task);
		if (rc) {
			if (0 == task->pid) {
				goto exit;
			}
			clog_warn (CLOG(CLOGGER_ID),
				   "Using partial context for PID %d", task->pid);
			rc = 0;
		}

		// The system owns a reference. When the task dies, we remove it.
		atomic_inc (&task->refct);

		task->key = pid;
//		task->task_struct = task;
		g_hash_table_insert (gstate.context_lookup, (gpointer)task->key, task);
		// The table owns a reference to the task context.
//		atomic_inc (&task->refct);
	}

	evt->task = task;

	evt->cbi   = cbi;
	*event = evt;

exit:
	return rc;
}


/**
 *
 * Reads user memory. TODO: broken/limited on ARM.
 */
static char *
read_user_mem (vmi_instance_t vmi,
	       nvmi_event_t * evt,
	       addr_t va,
	       size_t maxlen,
	       enum syscall_arg_type type)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	addr_t pa = 0;
	bool read_more = true;
	char * str = NULL;
	addr_t dtb = 0;
	char buf[16] = {0};
	size_t sz = 0;

#if defined(X86_64) || defined(EXPERIMENTAL_READ_USERMEM)
	// Actually try to pull the contents out of user memory

	// TODO: use a faster technique - ideally calling this while target process is in scope but 
	str = vmi_read_str_va (vmi, va, evt->task->pid);
	if (NULL == str) {
		clog_info (CLOG(CLOGGER_ID),"Error: could not read string at %" PRIx64 " in PID %d",
			va, evt->task->pid);
		goto failsafe;
	}

	// Success, done
	goto exit;

#if 0 // below is a graveyard of various stuff that doesn't work on ARM
	
		// FIXME: fix user mem deref on ARM
	// TODO: clear out v2p cache prior to translation

	// use vmi_get_kernel_struct_offset, to find task->mm->pgd
	// ARM: vmi_pid_to_dtb broken
	// ARM: vmi_read is misdirected. dtb wrong?
	// recompile libvmi with VMI_DEBUG_PTLOOKUP enabled
/*
	status = vmi_pid_to_dtb (vmi, evt->task->pid, &dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_info (CLOG(CLOGGER_ID),"Error could get DTB for pid %ld", evt->task->pid);
		goto exit;
	}
*/
	dtb = evt->task->task_dtb;
	clog_debug (CLOG(CLOGGER_ID), "PID %ld --> DTB %lx",
		 evt->task->pid, dtb);

	vmi_v2pcache_flush (vmi, dtb);
	//vmi_v2pcache_flush (vmi,  ~0ull);

	access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB,
				 .dtb = dtb,
				 // .dtb = evt->r.arch.arm64.ttbr0,
				 .addr = va };
	// better to read directly into caller buffer

/*
//	str = vmi_read_str(vmi, &ctx);
//	if (VMI_FAILURE == status) {
	if (NULL == str) {
		rc = EIO;
		clog_info (CLOG(CLOGGER_ID),"Error could get PA from VA %" PRIx64 ".", va);
		goto exit;
	}
*/

	status = vmi_read (vmi, &ctx, sizeof(buf), buf, &sz);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID),"Error could read memory from VA %" PRIx64 ".", va);

		snprintf (buf, sizeof(buf), "*0x%" PRIx64, va);
		str = strdup (buf);
		goto exit;
	}

	clog_debug (CLOG(CLOGGER_ID), "Read string '%s' from memory", buf);
//	str = strdup ("junk");
	str = strdup (buf);
	goto exit;
/*
#if defined(X86_64) // INTEL

#  if 1 // x86: works
	str = vmi_read_str_va (vmi, va, evt->task->pid);
	if (NULL == str) {
		clog_info (CLOG(CLOGGER_ID),"Error: could not read string at %" PRIx64 " in PID %lx",
			va, evt->task->pid);
		goto exit;
	}
#  endif

#  if 0 // x86: works
	status = vmi_pid_to_dtb (vmi, evt->task->pid, &dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_info (CLOG(CLOGGER_ID),"Error could get DTB for pid %ld", evt->task->pid);
		goto exit;
	}

	access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB,
				 .dtb = dtb,
				 .addr = va };
	// better to read directly into caller buffer

	str = vmi_read_str(vmi, &ctx);
//	if (VMI_FAILURE == status) {
	if (NULL == str) {
		rc = EIO;
		clog_info (CLOG(CLOGGER_ID),"Error could get PA from VA %" PRIx64 ".", va);
		goto exit;
	}
//	status = vmi_pagetable_lookup (vmi, evt->r.ttrb1, va, &pa);
//	status = vmi_read_va (vmi, va, evt->r.ttbr1)
#  endif

//	clog_info (CLOG(CLOGGER_ID), "Successfully read string '%s' from mem (%lx pid %lx)",
//		 str, va, evt->task->pid);

#else // ARM
#endif
*/
#endif // 0

#else
#endif


failsafe:
	// An attempt to relay something to the caller
	snprintf (buf, sizeof(buf), "*0x%" PRIx64, va);
	str = strdup (buf);
	
exit:
	return str;
}


/**
 * cb_pre_instr_pt()
 *
 * Called at beginning of a syscall.
 * TODO: Shift as much of this work as possible to a worker thread.
 */
static void
cb_pre_instr_pt (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;

	// arg / cbi tells us whether this is syscall or special event
	nvmi_cb_info_t * cbi = (nvmi_cb_info_t *) arg;
	nvmi_event_t * evt = NULL;

	// Ugly impl first: clean this up later
	assert (NULL == cbi ||
		cbi->argct <= NUMBER_OF(nvmi_syscall_arg_regs));

	rc = cb_gather_context (vmi, event, cbi, &evt);
	if (rc) {
		goto exit;
	}

	if (NULL == cbi) {
		// We don't have any metadata on this event
		goto exit;
	}

	for (int i = 0; i < cbi->argct; ++i) {
		reg_t val = evt->r.syscall_args[i];
		char * buf = NULL;

		//clog_debug (CLOG(CLOGGER_ID), "Syscall processing arg %d, val=%lx", i, val);

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
		case NVMI_ARG_TYPE_PVOID:
			break;
		case NVMI_ARG_TYPE_STR:
			buf = read_user_mem (vmi, evt, val, 0, 0);
			if (NULL == buf) {
				clog_warn (CLOG(CLOGGER_ID), "Failed to read str syscall arg");
				continue;
			}
			// Only worry about 1 dereferenced pointer, for now
			evt->mem_ofs[i] = 0;
			evt->arg_lens[i] = MIN(sizeof(evt->mem), strlen(buf));
			strncpy (evt->mem, buf, evt->arg_lens[i]);
			free (buf);
			break;
		case NVMI_ARG_TYPE_SA: {
#if 0
			struct addrinfo_in6 ai;
			struct addrinfo *res;

			status = vmi_read_va (vmi,
					      val,
					      evt->task->pid,
					      sizeof(ai),
					      &ai,
					      NULL);
			if (VMI_FAILURE == status ) {
				clog_warn (CLOG(CLOGGER_ID), "Failed to read addrinfo struct");
				continue;
			}

			rc = getaddrinfo (NULL, NULL, (const struct addrinfo *) &ai, &res);
			if (rc) {
				clog_warn (CLOG(CLOGGER_ID), "Failed to decode addrinfo struct");
				continue;
			}

			printf ("\targ %d: %s", i, res->ai_cannonname);
			freeaddrinfo (res);
			break;
#endif
		}
		default:
			break;
		}
	}

	if (evt->task->pid == gstate.killpid &&
	    cbi->cb_type == NVMI_CALLBACK_SYSCALL &&
	    cbi->argct > 0                         )
	{
		// Kills the current domU process by corrupting its
		// state upon a syscall. May need further work.
		//
		// Reference linux kernel:
		// arch/x86/entry/entry_64.S
		// arch/arm64/kernel/entry.S

		// Clobber the pointer (void *) registers
		for (int i = 0; i < cbi->argct; ++i)
		{
			if (cbi->args[i].type != NVMI_ARG_TYPE_PVOID) { continue; }

			status = vmi_set_vcpureg (vmi, 0, nvmi_syscall_arg_regs[i], event->vcpu_id);
			if (VMI_FAILURE == status) {
				clog_warn (CLOG(CLOGGER_ID),"Failed to write syscall register #%d", i);
				break;
			}
		}
	}

	// The event owns a reference
	atomic_inc (&evt->task->refct);
	g_async_queue_push (gstate.event_queue, (gpointer) evt);

exit:
	return;
}


static void
cb_post_instr_pt (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	printf ("Post: Hit breakpoint: %s", (const char*) arg);
}


static int
instrument_special_point (const char *name, addr_t kva)
{
	int rc = ENOENT;
	nvmi_cb_info_t * cbi = NULL;

	for (int i = 0; i < NUMBER_OF(nvmi_special_cbs); ++i)
	{
		cbi = &nvmi_special_cbs[i];
		if (0 != strcmp(name, cbi->name))
		{
			continue;
		}

		rc = nif_enable_monitor (kva, name, cb_pre_instr_pt, cb_post_instr_pt, cbi);
		if (rc) {
			clog_warn (CLOG(CLOGGER_ID), "Failed to add pg/bp for %s at %" PRIx64 "", name, kva);
			goto exit;
		}
	}

exit:

	return rc;
}

static int
instrument_syscall (char *name, addr_t kva)
{
	int rc = 0;
	nvmi_cb_info_t * cbi = NULL;
	bool monitored = false;

	static bool prediscovery = false;
	static size_t nvmi_syscall_new = 0; // where to put new (incomplete) entries into table?

	if (!prediscovery) {
		prediscovery = true;
		for (int i = 0; i < NUMBER_OF(nvmi_syscalls); ++i) {
			if (strlen(nvmi_syscalls[i].name) > 0) {
				++nvmi_syscall_new;
			}
		}
	}

	// SyS --> sys
	for (int i = 0; i < 3; ++i) {
		name[i] = (char) tolower(name[i]);
	}

	if (strncmp (name, "sys_", 4)) {
		// mismatch
		rc = ENOENT;
		goto exit;
	}

	// Skip these symbols: they are not syscalls
	if (!strcmp(name,  "sys_call_table")          ||
	    !strncmp(name, "sys_dmi", 7)              ||
	    !strcmp(name,  "sys_tz")                  || /* used by gettimeofday */
	    !strcmp(name,  "sys_tracepoint_refcount") ||
	    !strcmp(name,  "sys_table")               ||
	    !strcmp(name,  "sys_perf_refcount_enter") ||
	    !strcmp(name,  "sys_perf_refcount_exit")  ||
	    !strcmp(name,  "sys_reg_genericv8_init")    )
	{
		// mismatch
		rc = ENOENT;
		goto exit;
	}

	//
	// We have a syscall
	//


	// Bail if we're already monitoring that point
	rc = nif_is_monitored (kva, &monitored);
	if (rc) {
		goto exit;
	}

	if (monitored) {
		clog_info (CLOG(CLOGGER_ID), "KVA %" PRIx64 " is alraedy monitored", kva);
		goto exit;
	}

	gstate.act_calls++;
	if (gstate.act_calls == NVMI_MAX_SYSCALL_CT-1) { // max syscalls that we want to monitor
		rc = ENOSPC;
		clog_info (CLOG(CLOGGER_ID), "Exceeding max allowed syscalls. Halting search.");
		goto exit;
	}

	// We've found a syscall, and we have its address. Now, find it in our syscall table
	for (int i = 0; i < nvmi_syscall_new; ++i) { //NUMBER_OF(nvmi_syscalls); ++i) {
		if (!strcmp(name, nvmi_syscalls[i].name)) {
			cbi = &nvmi_syscalls[i];
			break;
		}
	}

	// Now, with or without the syscall def, monitor this syscall
	clog_info (CLOG(CLOGGER_ID), "#%d: Monitoring symbol %s at %" PRIx64 "",
		 gstate.act_calls, name, kva);

	// Stage syscall dynamically; name only
	if (NULL == cbi) {
		clog_info (CLOG(CLOGGER_ID), "monitoring syscall %s without a template", name);
		cbi = &nvmi_syscalls[nvmi_syscall_new++];
		cbi->cb_type = NVMI_CALLBACK_SYSCALL;
		cbi->enabled = true;
		strncpy (cbi->name, name, SYSCALL_MAX_NAME_LEN);
	}

	if (!cbi->enabled) {
		rc = ENOENT; // not quite right
		goto exit;
	}

	rc = nif_enable_monitor (kva, name, cb_pre_instr_pt, cb_post_instr_pt, cbi);
	if (rc) {
		clog_warn (CLOG(CLOGGER_ID), "Failed to add pg/bp for %s at %" PRIx64 "", name, kva);
		goto exit;
	}

exit:
	return rc;
}


// TODO: move to rekall
// TODO: handle KASLR
static int
set_instrumentation_points (const char* mappath)
{
	FILE* input_file = NULL;
	char one_line[1024];
	char * nl = NULL;
	int rc = 0;

	input_file = fopen(mappath, "r+");
	if (NULL == input_file) {
		rc = EINVAL;
		clog_warn (CLOG(CLOGGER_ID), "Can't open system map file '%s'", mappath);
		goto exit;
	}

	while (fgets( one_line, sizeof(one_line), input_file) != NULL) {
		char * name = NULL;
		addr_t kva = 0;

		// sample line: "ffffffff81033570 T sys_mmap"
		name = strstr(one_line, " T ");
		if (NULL == name) { // find the global text section symbols
			continue;
		}
		*name = '\0';
		name += 3;

		// overwrite EOL with NULL char
		if (NULL != (nl = strchr(name, '\n')))
			*nl='\0';

		// line: "ffffffff81033570\0T sys_mmap\0"
		kva = (addr_t) strtoul(one_line, NULL, 16);

		//printf ("symbol: %s, addr %lx\n", name, kva);
		//if (0 == strcmp("sys_sendmsg", name)) { __asm__("int $3");}

		rc = instrument_special_point (name, kva);
		if (0 == rc) { // success
			continue;
		} else if (ENOENT != rc) {
			// failure for reason other than line mismatch
			goto exit;
		}

		// Otherwise, try to match with a syscall
		rc = instrument_syscall (name, kva);
		if (0 == rc) { // success
			continue;
		} else if (ENOENT != rc) {
			// failure for reason other than line mismatch
			goto exit;
		}
	} // while

	clog_info (CLOG(CLOGGER_ID), "Found %d syscalls to monitor", gstate.act_calls);
	rc = 0;

exit:
	if (NULL != input_file) {
		fclose(input_file);
	}

	return rc;
}


static int
consume_special_event (nvmi_event_t * evt)
{
	int rc = 0;
	nvmi_cb_info_t * cbi = evt->cbi;

	assert (cbi);
	assert (cbi->cb_type == NVMI_CALLBACK_SPECIAL);

	clog_info (CLOG(CLOGGER_ID), "special event %s occurred in pid=%d comm=%s",
		   cbi->name, evt->task->pid, evt->task->comm);

	if (cbi == &nvmi_special_cbs[NVMI_DO_EXIT_IDX]) {
		// handle process destruction
		clog_info (CLOG(CLOGGER_ID), "exit of process pid %ld proc %s",
			 evt->task->pid, evt->task->comm);

		if (evt->task->pid == gstate.killpid) {
			clog_info (CLOG(CLOGGER_ID), "Kill of process pid=%d succeeded", gstate.killpid);
			gstate.killpid = KILL_PID_NONE;
		}

		// we'll never see that task again....
		g_hash_table_remove (gstate.context_lookup, (gpointer) evt->task->key);
	}

	return rc;
}


static int
consume_syscall_event (nvmi_event_t * evt)
{
	int rc = 0;
	nvmi_cb_info_t * cbi = evt->cbi;
	char buf[1024] = {0};
	char buf2[512];

	assert (cbi);
	assert (cbi->cb_type == NVMI_CALLBACK_SYSCALL);

	snprintf (buf, sizeof(buf), "syscall=%s(", cbi->name);

	for (int i = 0; i < cbi->argct; ++i) {
		reg_t val = evt->r.syscall_args[i];

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_STR: { // char *
			const char * str = (const char *) &(evt->mem[ evt->mem_ofs[i]]);
			if (strlen(str) > 0) {
				snprintf (buf2, sizeof(buf2) - 1, " \"%s\",", str);
				strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);
			}
			break;
		}


#if 0
		case NVMI_ARG_TYPE_SA: {

			struct addrinfo_in6 ai;
			struct addrinfo *res;

			status = vmi_read_va (vmi,
					      val,
					      evt->task->pid,
					      sizeof(ai),
					      &ai,
					      NULL);
			if (VMI_FAILURE == status ) {
				clog_warn (CLOG(CLOGGER_ID), "Failed to read addrinfo struct");
				continue;
			}

			rc = getaddrinfo (NULL, NULL, (const struct addrinfo *) &ai, &res);
			if (rc) {
				clog_warn (CLOG(CLOGGER_ID), "Failed to decode addrinfo struct");
				continue;
			}

			//printf ("\targ %d: %s", i+1, res->ai_cannonname);
			freeaddrinfo (res);
			break;
		}

#endif
		case NVMI_ARG_TYPE_SCALAR:
		case NVMI_ARG_TYPE_PVOID:
		case NVMI_ARG_TYPE_SA: // for now, don't deref SA
		default:
			//clog_info (CLOG(CLOGGER_ID), "\targ %d: %lx", i+1, val);
			snprintf (buf2, sizeof(buf2), " %lx,", val);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);
			break;
		} // switch
	} // for

#if defined(ARM64)
	snprintf (buf2, sizeof(buf2), ")	proc=%s	pid=%d	 TTBR0=%" PRIx32 "	TTBR1=%" PRIx32 "",
		  evt->task->comm, evt->task->pid, evt->r.arm.r.ttbr0, evt->r.arm.r.ttbr1);
#else
	snprintf (buf2, sizeof(buf2), ")	proc=%s		pid=%d		CR3=%" PRIx64 "",
		  evt->task->comm, evt->task->pid, evt->r.x86.r.cr3);
#endif
	strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

	if (gstate.use_comms) {
		rc = zmq_send (gstate.zmq_event_socket, buf, strlen(buf)+1, 0);
		if (rc < 0) {
			clog_warn (CLOG(CLOGGER_ID),"zmq_send() failed: %d", rc);
		}
	}

	////
	clog_info (CLOG(CLOGGER_ID), "%s", buf);

//exit:
	return rc;
}

/**
 * nvmi_event_consumer()
 *
 * Consumes events produced by pre_instr_cb()
 */
static gpointer
nvmi_event_consumer (gpointer data)
{
	gpointer rv = NULL;
	nvmi_cb_info_t * cbi = NULL;

	int rc = 0;

	clog_info (CLOG(CLOGGER_ID), "Begining event consumer loop");

	// Monitor gstate.interrupted
	while (!gstate.interrupted || gstate.nif_busy) {
		nvmi_event_t * evt = (nvmi_event_t *)
			g_async_queue_timeout_pop (gstate.event_queue, NVMI_EVENT_QUEUE_TIMEOUT_uS);
		if (NULL == evt) {
			// Nothing in queue. Is it time to return yet?
			continue;
		}

		// Process the event
		assert (evt);
		assert (evt->cbi);
		cbi = evt->cbi;

		switch (cbi->cb_type)
		{
		case NVMI_CALLBACK_SPECIAL:
			rc = consume_special_event (evt);
			break;
		case NVMI_CALLBACK_SYSCALL:
			rc = consume_syscall_event (evt);
			break;
		default:
			break;
		}

		// destroy the event: TODO - fix refct mismanagement!!
		//		deref_task_context ((gpointer)&evt->task);
		//		__sync_fetch_and_sub (&evt->task->refct, 1);

		//deref_task_context ((gpointer) evt->task);
//		free_task_context (evt->task);
		g_slice_free (nvmi_event_t, evt);
	} // while

exit:
	clog_info (CLOG(CLOGGER_ID), "Completed event consumer loop");

	// Event socket
	clog_info (CLOG(CLOGGER_ID), "Closing event socket");
	if (gstate.zmq_event_socket) {
		zmq_close (gstate.zmq_event_socket);
	} 
	gstate.zmq_event_socket  = NULL;

	return NULL;
}

static void
nvmi_main_fini (void)
{
	// releasing queue causes event consumer to return
	if (gstate.event_queue) {
		g_async_queue_unref (gstate.event_queue);
		gstate.event_queue = NULL;
	}
	clog_info (CLOG(CLOGGER_ID), "Event queue dereferenced");

	if (gstate.consumer_thread) {
		clog_info (CLOG(CLOGGER_ID), "Giving consumer thread time to leave.");
		g_thread_join (gstate.consumer_thread);
		//usleep(1);
		clog_info (CLOG(CLOGGER_ID), "Consumer thread joined");
		gstate.consumer_thread = NULL;
	}

	if (gstate.context_lookup) {
		g_hash_table_destroy (gstate.context_lookup);
		gstate.context_lookup = NULL;
		clog_info (CLOG(CLOGGER_ID), "Context lookup table destroyed");
	}

	clog_info (CLOG(CLOGGER_ID), "main cleanup complete");
}

static int
nvmi_main_init (void)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	vmi_instance_t vmi;

	// Handle ctrl+c properly
	gstate.act.sa_handler = close_handler;
	gstate.act.sa_flags = 0;
	sigemptyset(&gstate.act.sa_mask);
	sigaction(SIGHUP,  &gstate.act, NULL);
	sigaction(SIGTERM, &gstate.act, NULL);
	sigaction(SIGINT,  &gstate.act, NULL);
	sigaction(SIGALRM, &gstate.act, NULL);

	rc = nif_get_vmi (&vmi);
	if (rc) {
		goto exit;
	}

	gstate.killpid = KILL_PID_NONE;
	gstate.context_lookup = g_hash_table_new_full (NULL, // hash
						       NULL, // key equal
						       NULL, // key destroy
						       NULL); //deref_task_context); // TODO: impl ctx refct

	status |= vmi_get_kernel_struct_offset (vmi, "task_struct", "comm", &gstate.task_name_ofs);
	status |= vmi_get_kernel_struct_offset (vmi, "task_struct", "pid",  &gstate.task_pid_ofs);
	status |= vmi_get_kernel_struct_offset (vmi, "task_struct", "mm",   &gstate.task_mm_ofs);
	status |= vmi_get_kernel_struct_offset (vmi, "mm_struct",   "pgd",  &gstate.mm_pgd_ofs);

	if (VMI_FAILURE == status) {
		clog_warn (CLOG(CLOGGER_ID), "Failed to get offset");
		rc = EIO;
		goto exit;
	}
	assert (gstate.task_name_ofs &&
		gstate.task_pid_ofs  &&
		gstate.task_mm_ofs   &&
		gstate.mm_pgd_ofs );

#if !defined(ARM64)
	status = vmi_translate_ksym2v(vmi, "per_cpu__current_task", &gstate.va_current_task);
	if (VMI_FAILURE == status) {
		status = vmi_translate_ksym2v(vmi, "current_task", &gstate.va_current_task);
	}

	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID),"Error could get the current_task offset.");
		goto exit;
	}
	assert (gstate.va_current_task);
#endif

	gstate.event_queue = g_async_queue_new ();
	gstate.consumer_thread = g_thread_new ("consumer", nvmi_event_consumer, NULL);

exit:
	return rc;
}

static gpointer
comms_request_servicer (gpointer data)
{
    int rc = 0;

    while (!gstate.interrupted) {
        char msg[30] = {0};
        vmi_pid_t pid = -1;

	rc = zmq_recv (gstate.zmq_request_socket, msg, sizeof(msg), 0);
        if (rc <= 0) {
		clog_info (CLOG(CLOGGER_ID), "Request servicer thread bailing out");
		break;
        }

        //
        // Set global killpid: now syscall hook will watch for this pid
        //

        pid = *(vmi_pid_t*) msg;
        clog_warn (CLOG(CLOGGER_ID), "Received request to kill PID %d", pid);
        gstate.killpid = pid;
    }

exit:
    clog_info (CLOG(CLOGGER_ID), "Request servicer thread returning");

    // Request socket
    clog_info (CLOG(CLOGGER_ID), "Closing request socket");
    if (gstate.zmq_request_socket) {
	    zmq_close (gstate.zmq_request_socket);
    }
    gstate.zmq_request_socket  = NULL;

    //g_thread_exit (NULL);
    return NULL;
}

static void
comms_fini(void)
{
	if (!gstate.use_comms) {
		return;
	}

	clog_info (CLOG(CLOGGER_ID), "Beginning comms shutdown");

	// ZMQ context
	if (gstate.zmq_context) {
		// Notify all threads using ZMQ comms to stop and
		// close their respective sockets. zmq_term() waits
		// for all sockets opened with given context to be
		// closed.
		zmq_term (gstate.zmq_context);
		clog_info (CLOG(CLOGGER_ID), "All ZMQ sockets closed");
		zmq_ctx_destroy (gstate.zmq_context);
	}
	gstate.zmq_context = NULL;

	// Request servicer thread
	clog_info (CLOG(CLOGGER_ID), "Joining request servicer");
	if (gstate.request_service_thread) {
		g_thread_join (gstate.request_service_thread);
	}
	gstate.request_service_thread = NULL;


	clog_info (CLOG(CLOGGER_ID), "Comms shutdown complete");
}

static int
comms_init(void)
{
	int rc = 0;

	if (!gstate.use_comms) {
		goto exit;
	}

	// ZMQ context
	gstate.zmq_context = zmq_ctx_new();
	if (NULL == gstate.zmq_context) {
		rc = errno;
		clog_warn (CLOG(CLOGGER_ID), "zmq_ctx_new() failed");
		goto exit;
	}

	// Event socket
	gstate.zmq_event_socket = zmq_socket (gstate.zmq_context, ZMQ_PAIR);
	if (NULL == gstate.zmq_event_socket) {
		rc = zmq_errno();
		clog_warn (CLOG(CLOGGER_ID), "zmq_socket() failed");
		goto exit;
	}

	rc = zmq_bind (gstate.zmq_event_socket, ZMQ_EVENT_CHANNEL);
	if (rc) {
		clog_warn (CLOG(CLOGGER_ID), "zmq_connect(" ZMQ_EVENT_CHANNEL ") failed: %d", rc);
		goto exit;
	}

	// Request socket
	gstate.zmq_request_socket = zmq_socket (gstate.zmq_context, ZMQ_PAIR);
	if (NULL == gstate.zmq_request_socket) {
		rc = zmq_errno();
		clog_warn (CLOG(CLOGGER_ID), "zmq_socket() failed: %d", rc);
		goto exit;
	}

	rc = zmq_connect (gstate.zmq_request_socket, ZMQ_REQUEST_CHANNEL);
	if (rc) {
		clog_warn (CLOG(CLOGGER_ID), "zmq_connect(" ZMQ_REQUEST_CHANNEL ") failed: %d", rc);
		goto exit;
	}

	// Request servicer thread
	gstate.request_service_thread =
		g_thread_new ("request servicer", comms_request_servicer, NULL);

exit:
	return rc;
}


int
main (int argc, char* argv[])
{
	int rc = 0;
	status_t status;
	const char* name = argv[1];
	const char* in_path = argv[2];
	int opt = 0;
	int verbosity = 0;
	char * log_file = NULL;
	bool help = false;

	gstate.use_comms = true;
	
	while ((opt = getopt(argc, argv, ":o:sv")) != -1) {
		switch (opt) {
		case 'o':
			log_file = optarg;
			break;
		case 'v':
			++verbosity;
			break;
		case 's':
			gstate.use_comms = false;
			break;
		case '?':
			fprintf (stderr, "Illegal option: %c\n", optopt);
			help = true;
			break;
		}
	}

	if (help || argc - optind != 2) {
		printf("*** Numen Introspection Framework v2.0 ***\n\n");
		printf("Usage:\n");
		printf("%s [-v] [-o logfile] <domain name> <path to system_map>\n", argv[0]);
		printf("\t-v Increases verbosity of output logging, can be specified several times.\n");
		printf("\t-o Specifies file where output logging goes. Default is stderr.\n");
		printf("\t-s Run in silent mode - do not output events to brain.\n");
		return 1;
	}

	if (logger_init(log_file, verbosity)) {
		goto exit;
	}

	// Returns with VM suspended
	rc = nif_init (argv[optind], (bool *) &gstate.nif_busy);
	if (rc) {
		goto exit;
	}

	rc = nvmi_main_init ();
	if (rc) {
		goto exit;
	}

	rc = comms_init();
	if (rc) {
		goto exit;
	}

	rc = set_instrumentation_points (argv[optind+1]);
	if (rc) {
		goto exit;
	}

	// Resumes the VM, but returns with it paused
	rc = nif_event_loop();
	if (rc) {
		goto exit;
	}

exit:
	close_handler (0);

	// Resumes VM
	nif_fini();

	nvmi_main_fini();
	comms_fini();
	clog_info (CLOG(CLOGGER_ID), "Main completed");

	logger_fini();
	return rc;
}

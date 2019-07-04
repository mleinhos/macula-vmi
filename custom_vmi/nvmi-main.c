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
#include <endian.h>

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

#define TRIGGER_EVENT_LIMIT (500)

//
// Special instrumentation points
//
static nvmi_cb_info_t
nvmi_special_cbs[] =
{
#define NVMI_DO_EXIT_IDX 0
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "do_exit", .state = {.inv_cache = 1}, .argct = 0 },
#define NVMI_FD_INSTALL_IDX 1
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "fd_install", .argct = 6 },
#define NVMI_DO_FORK_IDX 2
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "_do_fork", .state = {.inv_cache = 1}, },
};


//
// Remaining TODO:
// - manage lifetime of process context
// - offload as much work as possible to consumer thread or to a post callback (notification of second VMI event)
//

typedef struct _nvmi_state {
	int act_calls;
	atomic_t event_id;

	// Signal handler
	struct sigaction act;
	volatile bool interrupted;
	volatile bool nif_busy;

	// VMI info
	addr_t task_name_ofs;
	addr_t task_pid_ofs;
	addr_t task_ppid_ofs;
	addr_t task_mm_ofs;
	addr_t mm_pgd_ofs;

	addr_t va_current_task;

	bool dump_stats;
	bool use_comms;
	void* zmq_context;
	void* zmq_event_socket;
	void* zmq_request_socket;

	// Maps easy-to-derive value to process context, e.g. curent
	// task_struct, or base kernel stack pointer.
	GHashTable * context_lookup;
	GRWLock context_lock;

	GThread * consumer_thread;

	// Don't let the internal event queue grow larger than this size
#define EVENT_QUEUE_MAX_LENGTH 100000
	GAsyncQueue * event_queue;

	// Handles inboudn requests over ZMQ
	GThread * request_service_thread;

	// Triggered processes: number of processes that have an
	// caused the switch to ACTIVE view.
	unsigned long triggered_procs;

	// The currently-requested monitoring level
	nvmi_level_t level;
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
	clog_info (CLOG(CLOGGER_ID), "Received notification to stop (%d), shutting down", sig);
	if (!gstate.interrupted) {
		gstate.interrupted = true;
		nif_stop();
	}
}

static void
dump_cb_stats(void)
{
	clog_warn (CLOG(CLOGGER_ID), "*************** BEGIN STATISTICS ****************" );

	for (int i = 0; i < NUMBER_OF(nvmi_syscalls); ++i)
	{
		nvmi_cb_info_t * cbi = &nvmi_syscalls[i];
		if (0 == cbi->hitct) continue;

		clog_warn (CLOG(CLOGGER_ID), "Called % 16d times: %s",
			   cbi->hitct, cbi->name);
	}

	for (int i = 0; i < NUMBER_OF(nvmi_special_cbs); ++i)
	{
		nvmi_cb_info_t * cbi = &nvmi_special_cbs[i];
		if (0 == cbi->hitct) continue;

		clog_warn (CLOG(CLOGGER_ID), "Called % 16d times: %s",
			   cbi->hitct, cbi->name);
	}
	clog_warn (CLOG(CLOGGER_ID), "Event count: %ld", gstate.event_id);
	clog_warn (CLOG(CLOGGER_ID), "*************** END STATISTICS ****************" );
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
	status  = vmi_get_vcpureg (vmi, &regs->arm.sp,     SP_USR, event->vcpu_id);
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
	status  = vmi_get_vcpureg (vmi, &regs->arm.r.ttbr0,  TTBR0,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.r.ttbr1,  TTBR1,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.r.sp,     SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.r.sp_el0, SP_EL0, event->vcpu_id);

	for (int i = 0; i < NUMBER_OF(x); ++i) {
		(void) vmi_get_vcpureg (vmi, &x[i], R0+i, event->vcpu_id);
		clog_debug (CLOG(CLOGGER_ID), "R%d = 0x%lx", i, x[i]);
	}

	clog_debug (CLOG(CLOGGER_ID), "Event: ttbr0 = 0x%lx", event->arm_regs->ttbr0);
	clog_debug (CLOG(CLOGGER_ID), "Event: ttbr1 = 0x%lx", event->arm_regs->ttbr1);
	clog_debug (CLOG(CLOGGER_ID), "Event: ttbcr = 0x%lx", event->arm_regs->ttbcr);
	clog_debug (CLOG(CLOGGER_ID), "Event: cpsr  = 0x%lx", event->arm_regs->cpsr);

	clog_debug (CLOG(CLOGGER_ID), "context: ttbr0   = %lx", regs->arm.r.ttbr0);
	clog_debug (CLOG(CLOGGER_ID), "context: ttbr1   = %lx", regs->arm.r.ttbr1);
	clog_debug (CLOG(CLOGGER_ID), "context: sp_el0  = %lx", regs->arm.r.sp_el0);
	clog_debug (CLOG(CLOGGER_ID), "context: sp      = %lx", regs->arm.r.sp);

#else
	status  = vmi_get_vcpureg (vmi, &regs->intel.cr3,     CR3,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->intel.sp,      RSP,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->intel.gs_base, GS_BASE, event->vcpu_id);
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
		clog_warn (CLOG(CLOGGER_ID),
			   "Failed to determine current task (from gs_base=%p + curr_task_offset=%p)",
			   regs->x86.r.gs_base + gstate.va_current_task);
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

#if 1
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

//	(*tinfo)->pid = pid;

	// Get current->comm
	// TODO: This is wrong
	pname = vmi_read_str_va (vmi, curr_task + gstate.task_name_ofs, 0);
	if (NULL == pname) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's comm at %" PRIx64 " + %lx",
			 (*tinfo)->task_struct, gstate.task_name_ofs);
		goto exit;
	}

//	clog_info (CLOG(CLOGGER_ID), "pid %d --> task %p, comm %s", pid, curr_task, pname);
	clog_info (CLOG(CLOGGER_ID), "pid %d --> task %p, comm %s",
		   (*tinfo)->pid, curr_task, pname);

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
	// Yes, these things are either wrong or cause an infinite
	// loop on ARM. On Intel the task_struct sometimes can't be
	// found for the call below.
	/*
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
	*/

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

	rc = cb_gather_registers (vmi, vmievent, &evt->r, argct);
	if (rc)
	{
		goto exit;
	}

	rc = cb_current_task (vmi, vmievent, &evt->r, &curr);
	if (rc)
	{
		clog_warn (CLOG(CLOGGER_ID), "Context could not be found");
		goto exit;
	}

	// Look for key in known contexts. If it isn't there, allocate
	// new nvmi_task_info_t and populate it.
	// TODO: enable caching by figuring out why it's broken on ARM (current != our key)

	g_rw_lock_reader_lock (&gstate.context_lock);
	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)curr);
	g_rw_lock_reader_unlock (&gstate.context_lock);

	if (NULL == task)
	{
		// Build new context
		rc = cb_build_task_context (vmi, &evt->r, curr, &task);
		if (rc)
		{
			if (0 == task->pid)
			{
				goto exit;
			}
			clog_warn (CLOG(CLOGGER_ID),
				   "Using partial context for PID %d", task->pid);
			rc = 0;
		}

		// The system owns a reference. When the task dies, we remove it.
		atomic_inc (&task->refct);

		task->key = curr;

		g_rw_lock_writer_lock (&gstate.context_lock);
		g_hash_table_insert (gstate.context_lookup, (gpointer)task->key, task);
		g_rw_lock_writer_unlock (&gstate.context_lock);

		// Policy
		task->trigger_event_limit = TRIGGER_EVENT_LIMIT;
		// The table owns a reference to the task context.
//		atomic_inc (&task->refct);
	}

	evt->task = task;

	evt->cbi   = cbi;
	*event = evt;

exit:
	return rc;
}


static int
find_task_context_by_pid (vmi_pid_t pid,
			  nvmi_task_info_t ** task)
{
	int rc = ENOENT;
	GList * tasks = NULL;
	GList * elem = NULL;

	// TODO: we're iterating over the contexts without a lock. Is this OK?
	g_rw_lock_reader_lock (&gstate.context_lock);

	tasks = g_hash_table_get_values (gstate.context_lookup);

	for (elem = tasks; elem != NULL; elem = elem->next)
	{
		nvmi_task_info_t * i = (nvmi_task_info_t *) elem->data;
		if (i->pid == pid)
		{
			*task = i;
			rc = 0;
			break;
		}
	}

	g_rw_lock_reader_unlock (&gstate.context_lock);

exit:
	g_list_free (tasks);
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
	int retry = 0;

#if defined(X86_64) || defined(EXPERIMENTAL_READ_USERMEM)
	// Actually try to pull the contents out of user memory

	// TODO: use a faster technique - ideally calling this while
	// target process is in scope but not directly in event
	// callback stack.
	//
	// TODO: write own impl of this function, using already-known
	// dtb and writing contents directly into caller-supplied
	// buffer.
	str = vmi_read_str_va (vmi, va, evt->task->pid);
	if (NULL == str)
	{
		// Maybe inject #PF too?
#if defined(X86_64) || defined(EXPERIMENTAL_ARM_FEATURES)
//		vmi_v2pcache_flush (vmi, evt->task->task_dtb);
		vmi_v2pcache_flush (vmi, ~0);
#else
		vmi_v2pcache_flush (vmi, ~0);
#endif
		vmi_pidcache_flush (vmi);
		vmi_rvacache_flush (vmi);
		// Try #2
		str = vmi_read_str_va (vmi, va, evt->task->pid);
		if (NULL == str)
		{
			clog_error (CLOG(CLOGGER_ID),
				    "Error: could not read string at %" PRIx64 " in PID %d",
				    va, evt->task->pid);
			goto failsafe;
		}
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
				 // .dtb = evt->r.arm.r.ttbr0,
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
	if (VMI_FAILURE == status)
	{
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Error could read memory from VA %" PRIx64 ".", va);

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

	//snprintf (buf, sizeof(buf), "*0x%" PRIx64, va);
	//str = strdup (buf);
	str = strdup ("[unknown]");

exit:
	return str;
}


static int
cb_pre_instr_kill_process (vmi_instance_t vmi, nvmi_event_t * evt, vmi_event_t* vmi_event)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;

	nvmi_cb_info_t * cbi = evt->cbi;
	bool attempted = false;

	// Kills the current domU process by corrupting its
	// state upon a syscall. May need further work.
	//
	// Reference Linux kernel:
	// arch/x86/entry/entry_64.S
	// arch/arm64/kernel/entry.S
	// Clobber the pointer (void *) registers
	// gstate.killpid stays set until the process dies (which is a special event)

	for (int i = 0; i < cbi->argct; ++i)
	{
		if (cbi->args[i].type != NVMI_ARG_TYPE_PVOID
		    && cbi->args[i].type != NVMI_ARG_TYPE_SA
		    && cbi->args[i].type != NVMI_ARG_TYPE_STR)
		{
			continue;
		}

		// It is feasible to kill the process. Do it
		// intermittenly to avoid loop between us and
		// the process or OS.
		if (++evt->task->kill_attempts % 3 != 0)
		{
			continue;
		}

#define NVMI_BOGUS_REG_VAL 0xbadc0ffee
		status = vmi_set_vcpureg (vmi, NVMI_BOGUS_REG_VAL, nvmi_syscall_arg_regs[i], vmi_event->vcpu_id);
		if (VMI_FAILURE == status)
		{
			rc = EIO;
			clog_warn (CLOG(CLOGGER_ID), "Failed to write syscall register #%d", i);
			break;
		}
		attempted = true;
	}

	if (attempted)
	{
		clog_warn (CLOG(CLOGGER_ID), "Attempted to kill process %d, comm=%s %d times",
			   evt->task->pid, evt->task->comm, evt->task->kill_attempts);
	}

exit:
	return rc;
}


/**
 * Policy!!
 */
static inline void
cb_update_trigger_state (nvmi_cb_info_t * cbi,
			 nvmi_task_info_t * task)
{
	// Sanity check: Can do neither in one CB, but can't do both!
	assert ((!cbi->state.trigger && !cbi->state.trigger_off) ||
		cbi->state.trigger != cbi->state.trigger_off);

	assert (task->trigger_event_limit > 0);

	if (cbi->state.trigger)
	{
		// Even if this has already caused a trigger, reset its stats
		if (!task->triggered)
		{
			clog_info (CLOG(CLOGGER_ID),
				   "Initiating trigger: event %s proc %s", cbi->name, task->comm);

			nif_set_level (NVMI_MONITOR_LEVEL_ACTIVE);
			gstate.level = NVMI_MONITOR_LEVEL_ACTIVE;
			atomic_inc (&gstate.triggered_procs);
			task->triggered = true;
		}
		task->events_since_trigger = 0;
	}
	else
	{
		// A non-triggering CB: track stats, switch back to TRIGGER view if needed
		unsigned long ct = atomic_inc (&task->events_since_trigger);

		if (ct > task->trigger_event_limit || cbi->state.trigger_off)
		{
			unsigned long pct = atomic_dec (&gstate.triggered_procs);

			clog_warn (CLOG(CLOGGER_ID),
				   "Saw over threshold of events, or event untriggers");

			task->triggered = false;
			task->events_since_trigger = 0;

			clog_info (CLOG(CLOGGER_ID),
				   "Dropping trigger: event %s proc %s", cbi->name, task->comm);

			if (0 == pct)
			{
				nif_set_level (NVMI_MONITOR_LEVEL_TRIGGERS);
				gstate.level = NVMI_MONITOR_LEVEL_TRIGGERS;
			}
		}
	}
}


/**
 * cb_pre_instr_pt()
 *
 * Called as entry point to any event callback.
 * TODO: Shift as much of this work as possible to a worker thread.
 */
static void
cb_pre_instr_pt (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	nvmi_cb_info_t * cbi = (nvmi_cb_info_t *) arg;
	nvmi_event_t * evt = NULL;
	int dataofs = 0;
	static nvmi_task_info_t * prev_ctx = NULL;
	static bool size_warning = false;

	assert (cbi);

	rc = cb_gather_context (vmi, event, cbi, &evt);
	if (rc)
	{
		goto exit;
	}

	atomic_inc (&cbi->hitct);
	cb_update_trigger_state (cbi, evt->task);

	// Only syscall events have arguments to parse
	for (int i = 0; i < cbi->argct; ++i)
	{
		reg_t val = evt->r.syscall_args[i];
		char * buf = NULL;

		//clog_debug (CLOG(CLOGGER_ID), "Syscall processing arg %d, val=%lx", i, val);

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
		case NVMI_ARG_TYPE_PVOID:
		case NVMI_ARG_TYPE_POLLFD:
		case NVMI_ARG_TYPE_FDSET:
			break;
		case NVMI_ARG_TYPE_STR:
			buf = read_user_mem (vmi, evt, val, 0, 0);
			if (NULL == buf)
			{
				clog_warn (CLOG(CLOGGER_ID), "Failed to read str syscall arg");
				continue;
			}

			evt->mem_ofs[i] = dataofs;
			evt->arg_lens[i] = MIN(sizeof(evt->mem) - dataofs, strlen(buf));
			strncpy (&evt->mem[dataofs], buf, evt->arg_lens[i]);
			free (buf);
			dataofs += evt->arg_lens[i];
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
			if (VMI_FAILURE == status)
			{
				clog_warn (CLOG(CLOGGER_ID), "Failed to read addrinfo struct");
				continue;
			}

			rc = getaddrinfo (NULL, NULL, (const struct addrinfo *) &ai, &res);
			if (rc)
			{
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

	if (evt->task->pending_kill_request_id && cbi->argct > 0)
	{
		(void) cb_pre_instr_kill_process (vmi, evt, event);
	}

	// The event owns a reference
	atomic_inc (&evt->task->refct);
	if (g_async_queue_length(gstate.event_queue) > EVENT_QUEUE_MAX_LENGTH)
	{
		if (!size_warning)
		{
			size_warning = true;
			clog_error (CLOG(CLOGGER_ID),
				   "Event queue length exceeds threshold (%d), new event(s) not pushed",
				   EVENT_QUEUE_MAX_LENGTH);
		}
		// !!!! Destroy the un-consumed event. Do not push it. !!!!
		g_slice_free (nvmi_event_t, evt);
		goto exit;
	}

	// (Re)set to emit warning next time capacity is reached
	size_warning = false;
	evt->id = atomic_inc (&gstate.event_id);
	g_async_queue_push (gstate.event_queue, (gpointer) evt);

/*
	// FIXME: determine when this really needs to be done

	//if (cbi->state.inv_cache)
	if (evt->task != prev_ctx)
	{
		prev_ctx = evt->task;
		//vmi_v2pcache_flush (vmi, ~0);
		vmi_pidcache_flush (vmi);
	}
*/
exit:
	return;
}


static void
cb_post_instr_pt (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	nvmi_cb_info_t * cbi = (nvmi_cb_info_t *) arg;
	clog_info (CLOG(CLOGGER_ID),
		   "Post CB for callback %s", cbi->name);
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

		rc = nif_enable_monitor (kva, name, cb_pre_instr_pt, cb_post_instr_pt, cbi, cbi->state.trigger);
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
		cbi->state.enabled = true;
		strncpy (cbi->name, name, SYSCALL_MAX_NAME_LEN);
	}

	if (!cbi->state.enabled) {
		rc = ENOENT; // not quite right
		goto exit;
	}

	rc = nif_enable_monitor (kva, name, cb_pre_instr_pt, NULL /*cb_post_instr_pt*/, cbi, cbi->state.trigger);
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


static void
populate_outbound_event (nvmi_event_t * inevent,
			 enum event_types etype,
			 event_t * outevent)
{
	struct timeval ts;

	// General event data
	outevent->len     = htobe32 (sizeof(*outevent));
	outevent->type    = htobe32 (etype);
	outevent->id      = htobe64 (inevent->id);
	outevent->context = htobe64 (inevent->task->pid);

	(void) gettimeofday (&ts, NULL);
	outevent->time.sec  = htobe64 (ts.tv_sec);
	outevent->time.usec = htobe64 (ts.tv_usec);
	strncpy (outevent->comm, inevent->task->comm, sizeof(outevent->comm));
}


static int
consume_special_event (nvmi_event_t * evt)
{
	int rc = 0;
	nvmi_cb_info_t * cbi = evt->cbi;
	event_t event = {0};
	bool event_ready = true;
	size_t size = offsetof(event_t, u);

	assert (cbi);
	assert (cbi->cb_type == NVMI_CALLBACK_SPECIAL);

	clog_info (CLOG(CLOGGER_ID), "special event %s occurred in pid=%d comm=%s",
		   cbi->name, evt->task->pid, evt->task->comm);

	if (cbi == &nvmi_special_cbs[NVMI_DO_EXIT_IDX])
	{
		// handle process destruction
		clog_info (CLOG(CLOGGER_ID), "exit of process pid %ld proc %s",
			   evt->task->pid, evt->task->comm);

		populate_outbound_event (evt, EVENT_TYPE_PROCESS_DEATH, &event);
		event.u.pcreate.uid = htobe64 (evt->task->uid);
		event.u.pcreate.gid = htobe64 (evt->task->gid);
		event.u.pcreate.pid = htobe64 (evt->task->pid);
		strncpy (event.u.pcreate.comm, evt->task->comm, sizeof(event.u.pcreate.comm));

		size += sizeof(process_death_event_t);
		event_ready = true;

		// Did brain ask for this destruction?
		if (evt->task->pending_kill_request_id) {
			response_t res = {0};
			res.id = htobe64 (evt->task->pending_kill_request_id);
			res.status = htobe32 (0);

			clog_info (CLOG(CLOGGER_ID), "Kill of process pid=%d succeeded", evt->task->pid);

			rc = zmq_send (gstate.zmq_request_socket, &res, sizeof(res), 0);
			if (rc < 0) {
				rc = errno;
				clog_warn (CLOG(CLOGGER_ID), "zmq_send() failed: %d", rc);
			}
			//		if (evt->task->pid == gstate.killpid) {
			//			clog_info (CLOG(CLOGGER_ID), "Kill of process pid=%d succeeded", evt->task->pid);
			//			gstate.killpid = KILL_PID_NONE;
		}

		// we'll never see that task again....
		g_rw_lock_writer_lock (&gstate.context_lock);
		g_hash_table_remove (gstate.context_lookup, (gpointer) evt->task->key);
		g_rw_lock_writer_unlock (&gstate.context_lock);
	}
	else if (cbi == &nvmi_special_cbs[NVMI_FD_INSTALL_IDX])
	{
		populate_outbound_event (evt, EVENT_TYPE_FILE_CREATE, &event);
		size += sizeof(file_creation_event_t);

#if defined(ARM64)
		event.u.fcreate.file_no = htobe32 (evt->r.syscall_args[0]);
#else
		event.u.fcreate.file_no = htobe32 (evt->r.x86.r.rdi);
#endif
	}
	else if (cbi == &nvmi_special_cbs[NVMI_DO_FORK_IDX])
	{
		populate_outbound_event (evt, EVENT_TYPE_PROCESS_CREATE, &event);
		size += sizeof(process_creation_event_t);
	}
	else
	{
		event_ready = false;
	}

	if (gstate.use_comms && event_ready)
	{
		event.len = htobe32 (size);
		rc = zmq_send (gstate.zmq_event_socket, &event, size, 0);
		if (rc < 0) {
			clog_warn (CLOG(CLOGGER_ID),"zmq_send() failed: %d", zmq_errno());
		}
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
	event_t event = {0};
	int dataofs = 0;
	size_t size = offsetof(event_t, u.syscall.data);

	assert (cbi);
	assert (cbi->cb_type == NVMI_CALLBACK_SYSCALL);

	if (gstate.dump_stats && evt->id % 100000 == 0)
	{
		dump_cb_stats();
	}

	populate_outbound_event (evt, EVENT_TYPE_SYSCALL, &event);

	snprintf (buf, sizeof(buf), "syscall=%s(", cbi->name);

	// Syscall-specific data
	strncpy (event.u.syscall.name, cbi->name, sizeof(event.u.syscall.name));
	event.u.syscall.arg_ct = htobe32 (cbi->argct);

	for (int i = 0; i < cbi->argct; ++i) {
		reg_t val = evt->r.syscall_args[i];

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_STR: { // char *
			uint8_t * bytes = &(evt->mem[ evt->mem_ofs[i] ]);
			size_t len = MIN (evt->arg_lens[i], sizeof(event.u.syscall.data) - dataofs);
			assert (len >= 0);

			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_STR);
			event.u.syscall.args[i].len  = htobe32 (len);
			event.u.syscall.args[i].val.offset = htobe64 (dataofs);

			if (len > 0)
			{
				event.u.syscall.flags |= SYSCALL_EVENT_FLAG_HAS_BUFFER;

				memcpy (&event.u.syscall.data[dataofs], bytes, len);

				snprintf (buf2, sizeof(buf2) - 1, " \"%s\",", (const char *)&event.u.syscall.data[dataofs]);
				strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

				if (dataofs + len >= sizeof(event.u.syscall.data))
				{
					event.u.syscall.flags |= SYSCALL_EVENT_FLAG_BUFFER_TRUNCATED;
					break;
				}
				dataofs += len;
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
		case NVMI_ARG_TYPE_SA: // FIXME: for now, don't deref SA
			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_SOCKADDR);
			event.u.syscall.args[i].len  = htobe32 (0);
			event.u.syscall.args[i].val.long_val = htobe64 (val);
			break;

		case NVMI_ARG_TYPE_SCALAR:
			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_SCALAR);
			event.u.syscall.args[i].val.long_val = htobe64 (val);

			snprintf (buf2, sizeof(buf2), " %lx,", val);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);
			break;

		case NVMI_ARG_TYPE_PVOID:
			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_PVOID);
			event.u.syscall.args[i].val.long_val = htobe64 (val);

			snprintf (buf2, sizeof(buf2), " %lx,", val);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);
			break;
		case NVMI_ARG_TYPE_FDSET:
			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_FDSET);
			break;
		case NVMI_ARG_TYPE_POLLFD:
			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_POLLFD);
			break;
		default:
			//clog_info (CLOG(CLOGGER_ID), "\targ %d: %lx", i+1, val);
			snprintf (buf2, sizeof(buf2), " %lx,", val);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

			event.u.syscall.args[i].len  = htobe32 (0);

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

	if (gstate.use_comms)
	{
		size += dataofs;
		event.len = htobe32 (size);
		rc = zmq_send (gstate.zmq_event_socket, &event, size, 0);
		if (rc < 0)
		{
			clog_warn (CLOG(CLOGGER_ID),"zmq_send() failed: %d", zmq_errno());
		}
	}

	clog_info (CLOG(CLOGGER_ID), "%s", buf);

	// If the syscall triggers a process context reset, destroy it now to force rebuild.
	if (cbi->state.reset_ctx)
	{
		clog_info (CLOG(CLOGGER_ID), "Invalidating context of task pid=%d", evt->task->pid);

		g_rw_lock_writer_lock (&gstate.context_lock);
		g_hash_table_remove (gstate.context_lookup, (gpointer) evt->task->key);
		g_rw_lock_writer_unlock (&gstate.context_lock);
	}

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
	g_async_queue_ref (gstate.event_queue);

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

	g_async_queue_ref (gstate.event_queue);

	return NULL;
}

static void
nvmi_main_fini (void)
{
	// FIXME:
	if (gstate.consumer_thread) {
		clog_info (CLOG(CLOGGER_ID), "Giving consumer thread time to leave.");
		//g_thread_join (gstate.consumer_thread);
		//usleep(1);
		clog_info (CLOG(CLOGGER_ID), "Consumer thread joined");
		gstate.consumer_thread = NULL;
	}
/*
	// releasing queue causes event consumer to return
	if (gstate.event_queue) {
		//g_async_queue_unref (gstate.event_queue);
		//gstate.event_queue = NULL;
	}
	clog_info (CLOG(CLOGGER_ID), "Event queue dereferenced");
*/
	if (gstate.context_lookup) {
		g_rw_lock_writer_lock (&gstate.context_lock);

		g_hash_table_destroy (gstate.context_lookup);
		gstate.context_lookup = NULL;

		g_rw_lock_writer_unlock (&gstate.context_lock);
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

	g_rw_lock_init (&gstate.context_lock);

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

	while (!gstate.interrupted)
	{
		request_t req = {0};
		response_t res = {0};
		bool response_created = false;
		nvmi_task_info_t * task = NULL;

		rc = zmq_recv (gstate.zmq_request_socket, &req, sizeof(req), ZMQ_DONTWAIT);
		if (rc <= 0)
		{
			if (EAGAIN == errno)
			{
				usleep(500);
				continue;
			}
			// Otherwise, fatal...
			clog_info (CLOG(CLOGGER_ID), "Request servicer thread bailing out");
			break;
		}

		// Change fields in-place
		req.id   = be64toh (req.id);
		req.cmd  = be32toh (req.cmd);
		req.arg1 = be64toh (req.arg1);
		req.arg2 = be64toh (req.arg2);

		switch (req.cmd)
		{
		case REQUEST_CMD_PROCKILL:
			clog_warn (CLOG(CLOGGER_ID), "Received request %lx to kill PID %d", req.id, req.arg1);

			// Set global killpid: now syscall hook will watch for this pid
			rc = find_task_context_by_pid (req.arg1, &task);
			if (rc) {
				res.id = htobe64 (req.id);
				res.status = htobe32 (rc);
				response_created = true;
				clog_warn (CLOG(CLOGGER_ID), "Request %lx indicated invalid PID %d: %d",
					   req.id, req.arg1, rc);
				break;
			}

			task->pending_kill_request_id = req.id;
			break;

		case REQUEST_CMD_SET_EVENT_LIMIT:
			clog_warn (CLOG(CLOGGER_ID), "Received request %lx to set event limit to %d", req.arg1);
			res.id = htobe64 (req.id);
			res.status = htobe32 (0);
			response_created = true;
			break;

		default:
			break;
		}

		if (response_created)
		{
			rc = zmq_send (gstate.zmq_request_socket, &res, sizeof(res), 0);
			if (rc < 0) {
				rc = errno;
				clog_warn (CLOG(CLOGGER_ID), "zmq_send() failed: %d", rc);
			}
		}
	} // while

exit:
	clog_info (CLOG(CLOGGER_ID), "Request servicer thread returning");

	// Request socket
	clog_info (CLOG(CLOGGER_ID), "Closing request socket");
	if (gstate.zmq_request_socket) {
		zmq_close (gstate.zmq_request_socket);
	}
	gstate.zmq_request_socket  = NULL;

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
		clog_warn (CLOG(CLOGGER_ID), "zmq_bind(" ZMQ_EVENT_CHANNEL ") failed: %d", rc);
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

	while ((opt = getopt(argc, argv, ":o:svd")) != -1) {
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
		case 'd':
			gstate.dump_stats = true;
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
		printf("\t-d Periodically dump callback statistics to logging target.\n");
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "linux"
 * End:
 */

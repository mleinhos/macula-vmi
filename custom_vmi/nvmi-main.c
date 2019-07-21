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
#include <json-c/json.h>

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

#ifndef TRIGGER_EVENT_LIMIT
#  define TRIGGER_EVENT_LIMIT 500
#endif // TRIGGER_EVENT_LIMIT

#ifndef DUMP_STATS_INTERVAL
#   define DUMP_STATS_INTERVAL 100000
#endif //  DUMP_STATS_INTERVAL

//
// Special instrumentation points
//
static nvmi_cb_info_t
nvmi_special_cbs[] =
{
#define NVMI_DO_EXIT_IDX 0
	// Included in trigger view, and also removes task from trigger consideration
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "do_exit",
	  .state = {.inv_cache = 1, .trigger = 1, .trigger_off = 1, .reset_ctx = 1} },
#define NVMI_FD_INSTALL_IDX 1
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "fd_install", .argct = 6 },
#define NVMI_DO_FORK_IDX 2
	{ .cb_type = NVMI_CALLBACK_SPECIAL, .name = "_do_fork",
	  .state = {.inv_cache = 1}, },
};


//
// Remaining TODO:
// - manage lifetime of process context
// - offload as much work as possible to consumer thread or to a post callback (notification of second VMI event)
//

typedef struct _nvmi_state
{
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

	// Rekall profile info
	struct json_object * rekall_root;

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

	if (logfile)
	{
		fprintf (stderr, "Initializing logging to %s, verbosity=%d\n",
			 logfile, verbosity_level);
		rc =  clog_init_path (CLOGGER_ID, logfile);
	}
	else
	{
		fprintf (stderr, "Initializing logging to stderr, verbosity=%d\n",
			 verbosity_level);
		rc = clog_init_fd (CLOGGER_ID, fileno(stderr));
	}
	if (rc)
	{
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
	nvmi_warn ("Received notification to stop (%d), shutting down", sig);
	if (!gstate.interrupted)
	{
		gstate.interrupted = true;
		//(void) clog_set_level (CLOGGER_ID, CLOG_DEBUG);
		//nvmi_warn ("Set logging verbosity to DEBUG for teardown");
		nif_stop();
	}
}

static void
dump_cb_stats(void)
{
	nvmi_warn ("*************** BEGIN STATISTICS ****************" );

	for (int i = 0; i < NUMBER_OF(nvmi_syscalls); ++i)
	{
		nvmi_cb_info_t * cbi = &nvmi_syscalls[i];
		if (0 == cbi->hitct)
		{
			continue;
		}

		nvmi_warn ("Called % 16d times: %s", cbi->hitct, cbi->name);
	}

	for (int i = 0; i < NUMBER_OF(nvmi_special_cbs); ++i)
	{
		nvmi_cb_info_t * cbi = &nvmi_special_cbs[i];
		if (0 == cbi->hitct)
		{
			continue;
		}

		nvmi_warn ("Called % 16d times: %s", cbi->hitct, cbi->name);
	}
	nvmi_warn ("Event count: %ld", gstate.event_id);
	nvmi_warn ("*************** END STATISTICS ****************" );
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

	for (int i = 0; i < argct; ++i)
	{
		status_t status = vmi_get_vcpureg (vmi,
						   &regs->syscall_args[i],
						   nvmi_syscall_arg_regs[i],
						   event->vcpu_id);
		if (VMI_FAILURE == status)
		{
			rc = EIO;
			goto exit;
		}
		//nvmi_debug ("syscall arg %d = %lx", i, regs->syscall_args[i]);
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
	if (VMI_SUCCESS != status)
	{
		rc = EFAULT;
		nvmi_warn ("vmi_get_vcpureg() failed");
		goto exit;
	}

/*
#if defined(ARM64)
	status  = vmi_get_vcpureg (vmi, &regs->arm.r.ttbr0,  TTBR0,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.r.ttbr1,  TTBR1,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.r.sp,     SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arm.r.sp_el0, SP_EL0, event->vcpu_id);

	for (int i = 0; i < NUMBER_OF(x); ++i)
{
		(void) vmi_get_vcpureg (vmi, &x[i], R0+i, event->vcpu_id);
		nvmi_debug ("R%d = 0x%lx", i, x[i]);
	}

	nvmi_debug ("Event: ttbr0 = 0x%lx", event->arm_regs->ttbr0);
	nvmi_debug ("Event: ttbr1 = 0x%lx", event->arm_regs->ttbr1);
	nvmi_debug ("Event: ttbcr = 0x%lx", event->arm_regs->ttbcr);
	nvmi_debug ("Event: cpsr  = 0x%lx", event->arm_regs->cpsr);

	nvmi_debug ("context: ttbr0   = %lx", regs->arm.r.ttbr0);
	nvmi_debug ("context: ttbr1   = %lx", regs->arm.r.ttbr1);
	nvmi_debug ("context: sp_el0  = %lx", regs->arm.r.sp_el0);
	nvmi_debug ("context: sp      = %lx", regs->arm.r.sp);

#else
	status  = vmi_get_vcpureg (vmi, &regs->intel.cr3,     CR3,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->intel.sp,      RSP,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->intel.gs_base, GS_BASE, event->vcpu_id);
#endif
	if (VMI_SUCCESS != status)
	{
		rc = EFAULT;
		nvmi_warn ("vmi_get_vcpureg() failed");
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

	if (0 == val)
	{
		nvmi_info ("**** Process pid=%ld comm=%s destroyed ****",
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
	status = vmi_read_addr_va (vmi,
				   regs->x86.r.gs_base + gstate.va_current_task,
				   0,
				   &local_curr);
	if (VMI_SUCCESS != status)
	{
		rc = EIO;
		nvmi_warn ("Failed to determine current task (from gs_base=%p + curr_task_offset=%p)",
			   regs->x86.r.gs_base + gstate.va_current_task);
		goto exit;
	}
#endif

	// Get current->pid
	status = vmi_read_32_va (vmi, local_curr + gstate.task_pid_ofs, 0, &local_pid);
	if (VMI_FAILURE == status)
	{
		rc = EFAULT;
		nvmi_warn ("Failed to read task's pid at %" PRIx64 " + %lx",
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

#else
	// x86 - slow: get current; alternate: get base of task kernel struct
	status_t status = vmi_read_addr_va (vmi,
					    regs->x86.r.gs_base + gstate.va_current_task,
					    0,
					    task);
	if (VMI_SUCCESS != status)
	{
		rc = EIO;
		task = NULL;
		nvmi_warn ("Failed to determine current task (from gs_base + curr_task_offset)");
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

	vmi_v2pcache_flush (vmi, ~0);
	vmi_pidcache_flush (vmi);
	vmi_rvacache_flush (vmi);

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

	// Get current->pid
	status = vmi_read_32_va (vmi,
				 curr_task + gstate.task_pid_ofs,
				 0,
				 &(*tinfo)->pid);
	if (VMI_FAILURE == status)
	{
		rc = EFAULT;
		nvmi_warn ("Failed to read task's pid at %" PRIx64 " + %lx",
			 (*tinfo)->task_struct, gstate.task_pid_ofs);
		goto exit;
	}

	// Get current->comm
	pname = vmi_read_str_va (vmi, curr_task + gstate.task_name_ofs, 0);
	if (NULL == pname)
	{
		rc = EFAULT;
		nvmi_warn ("Failed to read task's comm at %" PRIx64 " + %lx",
			 (*tinfo)->task_struct, gstate.task_name_ofs);
		goto exit;
	}

	nvmi_info ("pid %d --> task %p, comm %s",
		   (*tinfo)->pid, curr_task, pname);

	strncpy ((*tinfo)->comm, pname, sizeof((*tinfo)->comm));
	free (pname);

#if defined(EXPERIMENTAL_ARM_FEATURES) || defined(X86_64)
	// Get current->mm->pgd. LibVMI knows best. Sometimes this
	// puts LibVMI into an infinite loop, but grabbing
	// *(task->mm->pgd) on our own doesn't appear any better.

	status = vmi_pid_to_dtb (vmi, (*tinfo)->pid, &(*tinfo)->dtb);
	if (VMI_FAILURE == status)
	{
		rc = EIO;
		nvmi_warn ("Failed to find page base for task, pid=%ld",
			   (*tinfo)->pid);
		goto exit;
	}
	nvmi_debug ("vmi_pid_to_dtb: PID %d --> dtb %lx",
		    (uint32_t) (*tinfo)->pid,
		    (*tinfo)->dtb);

	nvmi_debug ("Build context: task=%lx (key) pid=%d comm=%s",
		    curr_task, (*tinfo)->pid, (*tinfo)->comm);
#endif

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
		nvmi_warn ("Context could not be found");
		goto exit;
	}

	// Look for key in known contexts. If it isn't there, allocate
	// new nvmi_task_info_t and populate it. Try a couple times if
	// we failed to get the full context.
	g_rw_lock_reader_lock (&gstate.context_lock);
	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)curr);
	g_rw_lock_reader_unlock (&gstate.context_lock);

	if (NULL == task ||
	    ((0 == task->pid) && task->events_since_trigger < 5))
	{
		// Build new context
		rc = cb_build_task_context (vmi, &evt->r, curr, &task);
		if (rc)
		{
			if (0 == task->pid)
			{
				goto exit;
			}
			nvmi_warn ("Using partial context for PID %d", task->pid);
			rc = 0;
		}

		// The system owns a reference. When the task dies, we remove it.
		atomic_inc (&task->refct);

		task->key = curr;

		g_rw_lock_writer_lock (&gstate.context_lock);
		g_hash_table_insert (gstate.context_lookup, (gpointer)task->key, task);
		g_rw_lock_writer_unlock (&gstate.context_lock);

		// Policy
		task->trigger_event_limit_active = true;
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
 * Reads the requested amount of memory, up to the end of the starting
 * page, directly into the caller-provided buffer.
 *
 * task - the task that owns the VA, or NULL if kernel memory
 */
static int
read_mem_one_page (IN vmi_instance_t vmi,
			IN nvmi_task_info_t * task,
			IN addr_t va,
			OUT uint8_t * buf,
			INOUT size_t * len)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	int remaining = *len;
	int ofs = va & (VMI_PS_4KB - 1);

	// At most, read to the end of the page
	int read_size = MIN (VMI_PS_4KB - ofs, *len);

	access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB,
				 .dtb = (task ? task->dtb : 0),
				 .addr = va };
	if (0 == ctx.dtb)
	{
		rc = EINVAL;
		nvmi_warn ("Failing request to read memory from proc %d, invalid DTB 0.",
			   task->pid);
		goto exit;
	}

	status = vmi_read (vmi, &ctx, read_size, buf, len);
	if (VMI_FAILURE == status)
	{
		rc = EIO;
		nvmi_warn ("Error could read memory from proc %d, DTB %" PRIx64 ", VA %" PRIx64 ".",
			   task->pid, task->dtb, va);
		goto exit;
	}

exit:
	return rc;
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
			nvmi_warn ("Failed to write syscall register #%d", i);
			break;
		}
		attempted = true;
	}

	if (attempted)
	{
		nvmi_warn ("Attempted to kill process %d, comm=%s %d times",
			   evt->task->pid, evt->task->comm, evt->task->kill_attempts);
	}

exit:
	return rc;
}


static bool
timeout_is_expired (const struct timeval * ts)
{
	struct timeval now = {0};

	gettimeofday (&now, NULL);

	return (now.tv_sec > ts->tv_sec ||
		(now.tv_sec == ts->tv_sec && now.tv_usec > ts->tv_usec));
}

/**
 * Policy!!
 *
 * FIXME: This code modifies a the NVMI task structure without a lock or reference.
 */
static inline void
cb_update_trigger_state (nvmi_cb_info_t * cbi,
			 nvmi_task_info_t * task)
{
	// N.B. An event can both cause and deactivate a trigger. Handle appropriately
	bool task_untriggered = false;
	nvmi_level_t new_level = NVMI_MONITOR_LEVEL_UNSET;

	// A non-triggering CB: track stats, switch back to TRIGGER view if needed
	unsigned long ct = atomic_inc (&task->events_since_trigger);

	assert (task->trigger_event_limit > 0);

	if (cbi->state.trigger)
	{
		// Even if this has already caused a trigger, reset its stats
		if (!task->triggered)
		{
			new_level = NVMI_MONITOR_LEVEL_ACTIVE;
			nvmi_warn ("Initiating trigger: event %s proc %s", cbi->name, task->comm);
			atomic_inc (&gstate.triggered_procs);
			task->triggered = true;
		}
		task->events_since_trigger = 0;
	}

	// Now test whether this event makes the level drop back
	// down. That can happen two ways: (1) event count has been
	// reached, or (2) trigger timeout has been reached.

	// N.B. trigger_event_limit_active starts off as "true"
	if (task->trigger_event_limit_active &&
	    ct == task->trigger_event_limit)
	{
		nvmi_warn ("Saw over threshold of events (%d)", task->trigger_event_limit);
		task->trigger_event_limit_active = false;
		task_untriggered = true;
	}

	if (task->trigger_timeout_active &&
	    timeout_is_expired (&task->trigger_timeout))
	{
		nvmi_warn ("Trigger timeout has expired for task pid=%ld", task->pid);
		task->trigger_timeout_active = false;
		task_untriggered = true;
	}

	// Other possibility: this event causes task to untrigger (e.g. process death)
	if (cbi->state.trigger_off)
	{
		nvmi_warn ("Event %s untriggers task", cbi->name);
		new_level = NVMI_MONITOR_LEVEL_TRIGGERS;
		task_untriggered = true;
	}

	if (task_untriggered)
	{
		unsigned long pct = atomic_dec (&gstate.triggered_procs);
		nvmi_warn ("Saw over threshold of events (task %s, count %d), event (%s) untriggers, or trigger timed out",
			   task->comm, ct, cbi->name);

		task->triggered = false;
		task->events_since_trigger = 0;

		if (0 == pct)
		{
			nvmi_warn ("No triggered processes remain");
			new_level = NVMI_MONITOR_LEVEL_TRIGGERS;
		}
	}

	if (NVMI_MONITOR_LEVEL_UNSET != new_level)
	{
		nif_set_level (new_level);
		gstate.level = new_level;
	}
}


/**
 *
 * Read string from memory until: (1) NULL terminator is found,
 * or (2) *len bytes have been exhausted. Works in conjunction with
 * read_mem_one_page() to avoid heap allocations and reading across page
 * boundaries if possible.
 */
static inline int
cb_read_str (IN vmi_instance_t vmi,
		  IN nvmi_task_info_t * task,
		  IN addr_t va,
		  OUT uint8_t * buf,
		  INOUT size_t * maxlen)
{
	int rc = 0;
	size_t origmax = *maxlen;
	size_t bytes_read = *maxlen;
	size_t ofs = 0; // offset we should read from / into ?
	size_t len = 0;

	if (0 == origmax)
	{
		rc = EINVAL;
		goto exit;
	}

	while (true)
	{
		len = 0;

		if (0 == bytes_read)
		{
			break;
		}

		rc = read_mem_one_page (vmi, task, va + ofs, &buf[ofs], &bytes_read);
		if (rc)
		{
			break;
		}

		// Find '\0'
		len = strnlen (&buf[ofs], origmax - ofs);
		if (len <= origmax - ofs)
		{
			*maxlen = ofs + len;
			break; // found
		}

		// Keep looking; grab more memory if space

		// We're at the end, and didn't find the NULL terminator!
		if (ofs + len == origmax - 1)
		{
			// At end of buffer. Truncate?
			buf[ofs + len] = '\0';
			break;
		}

		// \0 wasn't found, and there's more to read
		ofs += len;
		bytes_read = origmax - ofs;
	}

exit:
	return rc;
}


/**
 * cb_pre_instr_pt()
 *
 * Called as entry point to any event callback.
 * TODO: Shift as much of this work as possible to a worker thread.
 */
static void
cb_pre_instr_pt (vmi_instance_t vmi, vmi_event_t * event, void * arg)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	nvmi_cb_info_t * cbi = (nvmi_cb_info_t *) arg;
	nvmi_event_t * evt = NULL;
	size_t rem = sizeof (evt->mem);
	size_t len = 0;
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
	// TODO: move to event consumer: the event itself isn't needed or populated!
	cb_update_trigger_state (cbi, evt->task);

	// Only syscall events have arguments to parse
	for (int i = 0; i < cbi->argct; ++i)
	{
		reg_t val = evt->r.syscall_args[i];

		switch (cbi->args[i].type)
		{
		case NVMI_ARG_TYPE_SCALAR:
		case NVMI_ARG_TYPE_PVOID:
		case NVMI_ARG_TYPE_POLLFD:
		case NVMI_ARG_TYPE_FDSET:
			break;
		case NVMI_ARG_TYPE_STR:
#if defined(EXPERIMENTAL_ARM_FEATURES) || defined(X86_64)
			rc = cb_read_str (vmi, evt->task, val, &evt->mem[dataofs], &rem);
#endif
			if (rc)
			{
				// emit a zero-length string in evt struct
				continue;
			}

			evt->mem_ofs[i] = dataofs;
			evt->arg_lens[i] = rem;
			dataofs += rem;
			rem = sizeof(evt->mem) - dataofs;
			break;
		case NVMI_ARG_TYPE_SA:
		{
			// Read raw sockaddr into event buffer. Process later upon consumption.
			nvmi_generic_addr_t * dst = (nvmi_generic_addr_t *) &evt->mem[dataofs];

			// At this stage, just grab the sockaddr from the guest in binary form.
			access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB,
						 .dtb = evt->task->dtb,
						 .addr = val };

			status = vmi_read (vmi, &ctx, sizeof(struct sockaddr_in6), dst, &len);
			if (VMI_FAILURE == status)
			{
				nvmi_warn ("Failed to read sockaddr struct from pid=%d dtb=%lx va=%lx",
					   evt->task->pid, evt->task->dtb, val);
				continue;
			}

			// Success
			evt->mem_ofs[i] = dataofs;
			evt->arg_lens[i] = offsetof(sock_addr_t, addr) + len;
			dataofs += evt->arg_lens[i];
			rem = sizeof(evt->mem) - dataofs;
			break;
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
			nvmi_error ("Event queue length exceeds threshold (%d), new event(s) not pushed",
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
	nvmi_info ("Post CB for callback %s", cbi->name);
}


static int
instrument_special_point (char *name, addr_t kva)
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
			nvmi_warn ("Failed to add pg/bp for %s at %" PRIx64 "", name, kva);
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
	// Point to the base (legacy style) of the syscall name,
	// e.g. "sys_accept", from within __x64_sys_accept
	char * lookup = NULL;

	static bool prediscovery = false;
	static size_t nvmi_syscall_new = 0; // where to put new (incomplete) entries into table?

	if (!prediscovery)
	{
		prediscovery = true;
		for (int i = 0; i < NUMBER_OF(nvmi_syscalls); ++i)
		{
			if (strlen(nvmi_syscalls[i].name) > 0)
			{
				++nvmi_syscall_new;
			}
		}
	}

	// SyS --> sys
	for (int i = 0; i < 3; ++i)
	{
		name[i] = (char) tolower(name[i]);
	}

	if (!strncmp (name, "sys_", 4))
	{
		lookup = name; // point to sys_*
	}
	else if (!strncmp (name, "__x64_sys_", 10))
	{
		lookup = &name[6]; // point to sys_*
	}
	else
	{
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
	if (strlen (name) >= SYSCALL_MAX_NAME_LEN)
	{
		// Report a mismatch so the whole init doesn't fail
		rc = ENOENT;
		nvmi_error ("Symbol '%s' is too long", name);
		goto exit;
	}

	gstate.act_calls++;
	if (gstate.act_calls == NVMI_MAX_SYSCALL_CT-1)  // max syscalls that we want to monitor
	{
		rc = ENOSPC;
		nvmi_info ("Exceeding max allowed syscalls. Halting search.");
		goto exit;
	}

	// We've found a syscall, and we have its address. Now, find it in our syscall table
	for (int i = 0; i < nvmi_syscall_new; ++i)
	{
		if (!strcmp(lookup, nvmi_syscalls[i].name))
		{
			cbi = &nvmi_syscalls[i];
			break;
		}
	}

	// Now, with or without the syscall def, monitor this syscall
	nvmi_info ("#%d: Monitoring symbol %s at %" PRIx64 "",
		   gstate.act_calls, name, kva);

	// Stage syscall dynamically; add a minimal entry to the global array
	if (NULL == cbi)
	{
		nvmi_info ("monitoring syscall %s without a template", name);
		cbi = &nvmi_syscalls[nvmi_syscall_new++];
		cbi->cb_type = NVMI_CALLBACK_SYSCALL;
		cbi->state.enabled = true;
		strncpy (cbi->name, name, SYSCALL_MAX_NAME_LEN);
	}

	if (!cbi->state.enabled)
	{
		rc = ENOENT; // not quite right
		goto exit;
	}

	rc = nif_enable_monitor (kva, name, cb_pre_instr_pt, NULL /*cb_post_instr_pt*/, cbi, cbi->state.trigger);
	if (rc)
	{
		nvmi_warn ("Failed to add pg/bp for %s at %" PRIx64 "", name, kva);
		goto exit;
	}

exit:
	return rc;
}


/**
 * Attempts to match the given symbol to a special instrumentation
 * point or a syscall. If it matched, returns 0. If it doesn't match,
 * returns ENOENT. If some other error happened, returns another error
 * code.
 */
static int
set_instr_point (char * symname,
		 addr_t kva)
{
	int rc = 0;
	bool monitored = false;

	// Bail if we're already monitoring the point
	rc = nif_is_monitored (kva, &monitored);
	if (0 == rc && monitored)
	{
		nvmi_info ("KVA %" PRIx64 " (%s) is alraedy monitored", kva, symname);
		goto exit;
	}

	rc = instrument_special_point (symname, kva);
	if (0 == rc)
	{
		// success: this is an special point
		goto exit;
	}
	else if (ENOENT != rc)
	{
		// failure for reason other than line mismatch
		goto exit;
	}

	// Otherwise, try to match with a syscall
	rc = instrument_syscall (symname, kva);
	if (0 == rc)
	{
		// success: this is a syscall
		goto exit;
	}
	else if (ENOENT != rc)
	{
		// failure for reason other than line mismatch
		goto exit;
	}

exit:
	return rc;
}


// TODO: handle KASLR
static int
set_instr_points_rekall (void)
{
	int rc = 0;
	struct json_object * rekall = NULL;
	struct json_object * structs = NULL;
	struct json_object * constants = NULL;
	struct json_object_iterator it;
	struct json_object_iterator it_end;

	if (!json_object_object_get_ex (gstate.rekall_root, "$CONSTANTS", &constants))
	{
		rc = EINVAL;
		fprintf (stderr, "Failed to find $CONSTANTS section\n");
		goto exit;
	}

	// Process every symbol: the instrumentation point setters get
	// to decide whether it should be hooked.
	it = json_object_iter_begin (constants);
	it_end = json_object_iter_end (constants);

	while (!json_object_iter_equal (&it, &it_end))
	{
		char * symname = (char *) json_object_iter_peek_name(&it);
		unsigned long kva = json_object_get_int64(json_object_iter_peek_value(&it));

		// Make the addr canonical.
		if ( VMI_GET_BIT(kva, 47) )
		{
			kva |= 0xffff000000000000;
		}

		nvmi_debug ("Processing symbol=%s kva=%lx", symname, kva);

		rc = set_instr_point (symname, kva);
		if (rc != 0 && rc != ENOENT)
		{
			nvmi_warn ("Failed on symbol %s", symname);
			goto exit;
		}

		json_object_iter_next (&it);
	}

	nvmi_info ("Found %d syscalls to monitor", gstate.act_calls);
	rc = 0;

exit:
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

	nvmi_info ("special event %s occurred in pid=%d comm=%s",
		   cbi->name, evt->task->pid, evt->task->comm);

	if (cbi == &nvmi_special_cbs[NVMI_DO_EXIT_IDX])
	{
		// handle process destruction
		nvmi_info ("exit of process pid %ld proc %s",
			   evt->task->pid, evt->task->comm);

		populate_outbound_event (evt, EVENT_TYPE_PROCESS_DEATH, &event);
		event.u.pcreate.uid = htobe64 (evt->task->uid);
		event.u.pcreate.gid = htobe64 (evt->task->gid);
		event.u.pcreate.pid = htobe64 (evt->task->pid);
		strncpy (event.u.pcreate.comm, evt->task->comm, sizeof(event.u.pcreate.comm));

		size += sizeof(process_death_event_t);
		event_ready = true;

		// Did brain ask for this destruction?
		if (evt->task->pending_kill_request_id)
		{
			response_t res = {0};
			res.id = htobe64 (evt->task->pending_kill_request_id);
			res.status = htobe32 (0);

			nvmi_info ("Kill of process pid=%d succeeded", evt->task->pid);

			rc = zmq_send (gstate.zmq_request_socket, &res, sizeof(res), 0);
			if (rc < 0)
			{
				rc = errno;
				nvmi_warn ("zmq_send() failed: %d", rc);
			}
		}

		// we'll never see that task again....
		g_rw_lock_writer_lock (&gstate.context_lock);
		g_hash_table_remove (gstate.context_lookup, (gpointer) evt->task->key);
		g_rw_lock_writer_unlock (&gstate.context_lock);
	}
	else if (cbi == &nvmi_special_cbs[NVMI_FD_INSTALL_IDX])
	{
		reg_t fd = 0;
		populate_outbound_event (evt, EVENT_TYPE_FILE_CREATE, &event);
		size += sizeof(file_creation_event_t);

#if defined(ARM64)
		fd = evt->r.syscall_args[0];
#else
		fd = evt->r.x86.r.rdi;
#endif
		event.u.fcreate.file_no = htobe32 (fd);
		nvmi_info ("fd=%d installed into process pid=%ld comm=%s",
			   fd, evt->task->pid, evt->task->comm);
	}
	else if (cbi == &nvmi_special_cbs[NVMI_DO_FORK_IDX])
	{
		populate_outbound_event (evt, EVENT_TYPE_PROCESS_CREATE, &event);
		size += sizeof(process_creation_event_t);
		nvmi_info ("fork() in process pid=%ld comm=%s",
			   evt->task->pid, evt->task->comm);
	}
	else
	{
		event_ready = false;
	}

	if (gstate.use_comms && event_ready)
	{
		event.len = htobe32 (size);
		rc = zmq_send (gstate.zmq_event_socket, &event, size, 0);
		if (rc < 0)
		{
			nvmi_warn ("zmq_send() failed: %d", zmq_errno());
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
	int input_ofs = 0;
	int output_ofs = 0;
	size_t size = offsetof(event_t, u.syscall.data);
	size_t len = 0;

	assert (cbi);
	assert (cbi->cb_type == NVMI_CALLBACK_SYSCALL);

	if (gstate.dump_stats && evt->id % DUMP_STATS_INTERVAL == 0)
	{
		dump_cb_stats();
	}

	populate_outbound_event (evt, EVENT_TYPE_SYSCALL, &event);

	snprintf (buf, sizeof(buf), "syscall=%s(", cbi->name);

	// Syscall-specific data
	strncpy (event.u.syscall.name, cbi->name, sizeof(event.u.syscall.name));
	event.u.syscall.arg_ct = htobe32 (cbi->argct);

	for (int i = 0; i < cbi->argct; ++i)
	{
		reg_t val = evt->r.syscall_args[i];

		switch (cbi->args[i].type)
		{
		case NVMI_ARG_TYPE_STR: // char *
		{
			uint8_t * bytes = &(evt->mem[ evt->mem_ofs[i] ]);
			len = MIN (evt->arg_lens[i], sizeof(event.u.syscall.data) - output_ofs);
			assert (len >= 0);

			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_STR);
			event.u.syscall.args[i].len  = htobe32 (len);
			event.u.syscall.args[i].val.offset = htobe64 (output_ofs);

			if (len > 0)
			{
				event.u.syscall.flags |= SYSCALL_EVENT_FLAG_HAS_BUFFER;

				memcpy (&event.u.syscall.data[output_ofs], bytes, len);

				snprintf (buf2, sizeof(buf2) - 1, " \"%s\",", (const char *)&event.u.syscall.data[output_ofs]);
				strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

				if (output_ofs + len >= sizeof(event.u.syscall.data))
				{
					event.u.syscall.flags |= SYSCALL_EVENT_FLAG_BUFFER_TRUNCATED;
					break;
				}
				input_ofs += len;
				output_ofs += len;
			}
			break;
		}
		case NVMI_ARG_TYPE_SA:
		{
			nvmi_generic_addr_t * src = (nvmi_generic_addr_t *) &evt->mem[ evt->mem_ofs[i] ];
			sock_addr_t * dst = (sock_addr_t *) &event.u.syscall.data [output_ofs];
			const char * sastr = NULL;

			switch (src->s4.sin_family)
			{
			case AF_UNIX:
				dst->family = htobe16 (SOCK_TYPE_UNIX);
				dst->port   = 0;
				sastr = strncpy ((char *) &dst->addr, src->su.sun_path, SYSCALL_MAX_ARG_BUF - output_ofs);
				break;
			case AF_INET:
				dst->family = htobe16 (SOCK_TYPE_IP4);
				dst->port    = htobe16 (src->s4.sin_port);
				sastr = inet_ntop (AF_INET, &(src->s4.sin_addr),
						   (char *) &dst->addr, SYSCALL_MAX_ARG_BUF - output_ofs);
				break;
			case AF_INET6:
				dst->family = htobe16 (SOCK_TYPE_IP6);
				dst->port   = htobe16 (src->s6.sin6_port);
				sastr = inet_ntop (AF_INET6, &(src->s6.sin6_addr),
						   (char *) &dst->addr, SYSCALL_MAX_ARG_BUF - output_ofs);
				break;
			default:
				dst->family = 0;
				dst->port   = 0;
				break;
			}

			if (NULL == sastr)
			{
				nvmi_warn ("Failed to read process socket address, pid=%d comm=%s",
					   evt->task->pid, evt->task->comm);
			}

			len = offsetof(sock_addr_t, addr) + (sastr ? strlen(sastr) : 0);

			snprintf (buf2, sizeof(buf2) - 1, " \"%s\",", (const char *)dst->addr);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_SOCKADDR);
			event.u.syscall.args[i].len  = htobe32 (len);
			event.u.syscall.args[i].val.offset = htobe64 (output_ofs);

			input_ofs += len;
			output_ofs += len;
			break;
		}
		case NVMI_ARG_TYPE_PVOID:
		case NVMI_ARG_TYPE_SCALAR:
			event.u.syscall.args[i].type = htobe32 (SYSCALL_ARG_TYPE_SCALAR);
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
			//nvmi_info ("\targ %d: %lx", i+1, val);
			snprintf (buf2, sizeof(buf2), " %lx,", val);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

			event.u.syscall.args[i].len  = htobe32 (0);

			break;
		} // switch
	} // for

#if defined(ARM64)
	snprintf (buf2, sizeof(buf2), ")	proc=%s	pid=%d	 TTBR0=%" PRIx32 "	TTBR1=%" PRIx32 "",
		  evt->task->comm, evt->task->pid, evt->task->dtb, evt->r.arm.r.ttbr1);
#else
	snprintf (buf2, sizeof(buf2), ")	proc=%s		pid=%d		CR3=%" PRIx64 "",
		  evt->task->comm, evt->task->pid, evt->r.x86.r.cr3);
#endif
	strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

	if (gstate.use_comms)
	{
		size += output_ofs;;
		event.len = htobe32 (size);
		rc = zmq_send (gstate.zmq_event_socket, &event, size, 0);
		if (rc < 0)
		{
			nvmi_warn ("zmq_send() failed: %d", zmq_errno());
		}
	}

	nvmi_info ("%s", buf);
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

	nvmi_info ("Begining event consumer loop");
	g_async_queue_ref (gstate.event_queue);

	// Monitor gstate.interrupted
	while (!gstate.interrupted || gstate.nif_busy)
	{
		nvmi_event_t * evt = (nvmi_event_t *)
			g_async_queue_timeout_pop (gstate.event_queue, NVMI_EVENT_QUEUE_TIMEOUT_uS);
		if (NULL == evt)
		{
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

		// If the event triggers a process context reset, destroy it now to force rebuild.
		if (cbi->state.reset_ctx)
		{
			nvmi_info ("Invalidating context of task pid=%d", evt->task->pid);

			g_rw_lock_writer_lock (&gstate.context_lock);
			g_hash_table_remove (gstate.context_lookup, (gpointer) evt->task->key);
			g_rw_lock_writer_unlock (&gstate.context_lock);
		}

		// All done with the event
		g_slice_free (nvmi_event_t, evt);
	} // while

exit:
	nvmi_info ("Completed event consumer loop");

	// Event socket
	nvmi_info ("Closing event socket");
	if (gstate.zmq_event_socket)
	{
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
	if (gstate.consumer_thread)
	{
		nvmi_info ("Giving consumer thread time to leave.");
		//g_thread_join (gstate.consumer_thread);
		//usleep(1);
		nvmi_info ("Consumer thread joined");
		gstate.consumer_thread = NULL;
	}

	// N.B. releasing queue causes event consumer to return

	if (gstate.context_lookup)
	{
		g_rw_lock_writer_lock (&gstate.context_lock);

		g_hash_table_destroy (gstate.context_lookup);
		gstate.context_lookup = NULL;

		g_rw_lock_writer_unlock (&gstate.context_lock);
		nvmi_info ("Context lookup table destroyed");
	}

	if (gstate.rekall_root)
	{
		json_object_put (gstate.rekall_root);
		gstate.rekall_root = NULL;
	}

	nvmi_info ("main cleanup complete");
}

static int
nvmi_main_init (void)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	vmi_instance_t vmi;
	const char * rekall_path = NULL;

	rc = nif_get_vmi (&vmi);
	if (rc)
	{
		goto exit;
	}

	// Handle ctrl+c properly
	gstate.act.sa_handler = close_handler;
	gstate.act.sa_flags = 0;
	sigemptyset(&gstate.act.sa_mask);
	sigaction(SIGHUP,  &gstate.act, NULL);
	sigaction(SIGTERM, &gstate.act, NULL);
	sigaction(SIGINT,  &gstate.act, NULL);
	sigaction(SIGALRM, &gstate.act, NULL);

	rekall_path = vmi_get_rekall_path (vmi);
	if (NULL == rekall_path)
	{
		rc = ENOENT;
		fprintf (stderr, "Failed to find rekall file. Was it included in the LibVMI profile?\n");
		goto exit;
	}

	gstate.rekall_root = json_object_from_file (rekall_path);
	if (NULL == gstate.rekall_root)
	{
		fprintf (stderr, "File %s is not a REKALL profile. Treating it as a Symbol map.\n",
			 rekall_path);
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

	if (VMI_FAILURE == status)
	{
		nvmi_warn ("Failed to get offset");
		rc = EIO;
		goto exit;
	}
	assert (gstate.task_name_ofs &&
		gstate.task_pid_ofs  &&
		gstate.task_mm_ofs   &&
		gstate.mm_pgd_ofs );

#if !defined(ARM64)
	status = vmi_translate_ksym2v(vmi, "per_cpu__current_task", &gstate.va_current_task);
	if (VMI_FAILURE == status)
	{
		status = vmi_translate_ksym2v(vmi, "current_task", &gstate.va_current_task);
	}

	if (VMI_FAILURE == status)
	{
		rc = EIO;
		nvmi_warn ("Error could get the current_task offset.");
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
			nvmi_info ("Request servicer thread bailing out");
			break;
		}

		// Change fields in-place
		req.id   = be64toh (req.id);
		req.cmd  = be32toh (req.cmd);
		req.arg1 = be64toh (req.arg1);
		req.arg2 = be64toh (req.arg2);

		// If the request modifies a task state, find that task here
		if (req.cmd & REQUEST_MODIFIES_TASK)
		{
			rc = find_task_context_by_pid (req.arg1, &task);
			if (rc)
			{
				res.id = htobe64 (req.id);
				res.status = htobe32 (rc);
				response_created = true;
				nvmi_warn ("Request %lx indicated invalid PID %d: %d",
					   req.id, req.arg1, rc);
				goto issue_response;
			}
		}

		// Most requests get an immediate response
		response_created = true;
			
		switch (req.cmd)
		{
		case REQUEST_CMD_PROCKILL:
			nvmi_warn ("Received request %lx to kill PID %d", req.id, req.arg1);
			task->pending_kill_request_id = req.id;
			response_created = false;
			break;
		case REQUEST_CMD_SET_PROC_EVENT_LIMIT:
			// arg1: pid, arg2: numerical limit
			nvmi_warn ("Received request %lx to set event limit to %d for pid=%ld",
				   req.id, req.arg2, req.arg1);
			task->trigger_event_limit_active = true;
			task->trigger_event_limit = req.arg2;

			res.id = htobe64 (req.id);
			res.status = htobe32 (0);
			break;
		case REQUEST_CMD_SET_PROC_TRIGGERED_TIMEOUT:
		{
			struct timeval time = {0};
			unsigned long ms = req.arg2;
			
			// arg1: pid, arg2: timeout in milliseconds
			gettimeofday (&time, NULL);
			nvmi_warn ("Received request %lx to set trigger timeout in pid=%ld %ld MS from now, curr time = %ld.%ld",
				   req.id, req.arg1, req.arg2, time.tv_sec, time.tv_usec);

			// Timeout: now + specified milliseconds. Add a MS back in due to precision loss.
			ms += time.tv_usec / 1000 + 1;

			// Handle overflow
			if (ms > 1000)
			{
				time.tv_sec += 1;
				ms -= 1000;
			}
			time.tv_usec = ms * 1000;
			task->trigger_timeout_active = true;
			task->trigger_timeout = time;

			nvmi_warn ("Request %lx: trigger timeout in pid=%ld set to %ld.%ld",
				   req.id, req.arg1, time.tv_sec, time.tv_usec);

			res.id = htobe64 (req.id);
			res.status = htobe32 (0);
			break;
		}
		default:
			break;
		}

	issue_response:
		if (response_created)
		{
			rc = zmq_send (gstate.zmq_request_socket, &res, sizeof(res), 0);
			if (rc < 0)
			{
				rc = errno;
				nvmi_warn ("zmq_send() failed: %d", rc);
			}
		}
	} // while

exit:
	nvmi_info ("Request servicer thread returning");

	// Request socket
	nvmi_info ("Closing request socket");
	if (gstate.zmq_request_socket)
	{
		zmq_close (gstate.zmq_request_socket);
	}
	gstate.zmq_request_socket  = NULL;

	return NULL;
}


static void
comms_fini(void)
{
	if (!gstate.use_comms)
	{
		return;
	}

	nvmi_info ("Beginning comms shutdown");

	// ZMQ context
	if (gstate.zmq_context)
	{
		// Notify all threads using ZMQ comms to stop and
		// close their respective sockets. zmq_term() waits
		// for all sockets opened with given context to be
		// closed.
		zmq_term (gstate.zmq_context);
		nvmi_info ("All ZMQ sockets closed");
		zmq_ctx_destroy (gstate.zmq_context);
	}
	gstate.zmq_context = NULL;

	// Request servicer thread
	nvmi_info ("Joining request servicer");
	if (gstate.request_service_thread)
	{
		g_thread_join (gstate.request_service_thread);
	}
	gstate.request_service_thread = NULL;


	nvmi_info ("Comms shutdown complete");
}

static int
comms_init(void)
{
	int rc = 0;

	if (!gstate.use_comms)
	{
		goto exit;
	}

	// ZMQ context
	gstate.zmq_context = zmq_ctx_new();
	if (NULL == gstate.zmq_context)
	{
		rc = errno;
		nvmi_warn ("zmq_ctx_new() failed");
		goto exit;
	}

	// Event socket
	gstate.zmq_event_socket = zmq_socket (gstate.zmq_context, ZMQ_PAIR);
	if (NULL == gstate.zmq_event_socket)
	{
		rc = zmq_errno();
		nvmi_warn ("zmq_socket() failed");
		goto exit;
	}

	rc = zmq_bind (gstate.zmq_event_socket, ZMQ_EVENT_CHANNEL);
	if (rc)
	{
		nvmi_warn ("zmq_bind(" ZMQ_EVENT_CHANNEL ") failed: %d", rc);
		goto exit;
	}

	// Request socket
	gstate.zmq_request_socket = zmq_socket (gstate.zmq_context, ZMQ_PAIR);
	if (NULL == gstate.zmq_request_socket)
	{
		rc = zmq_errno();
		nvmi_warn ("zmq_socket() failed: %d", rc);
		goto exit;
	}

	rc = zmq_connect (gstate.zmq_request_socket, ZMQ_REQUEST_CHANNEL);
	if (rc)
	{
		nvmi_warn ("zmq_connect(" ZMQ_REQUEST_CHANNEL ") failed: %d", rc);
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
	const char* domu = NULL;
	int opt = 0;
	int verbosity = 0;
	char * log_file = NULL;
	bool help = false;

	gstate.use_comms = true;

	while ((opt = getopt(argc, argv, ":o:svdh")) != -1)
	{
		switch (opt)
		{
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
		case 'h':
			help = true;
			break;
		case '?':
			fprintf (stderr, "Illegal option: %c\n", optopt);
			help = true;
			break;
		}
	}

	if (help || argc - optind != 1)
	{
		printf("*** Numen Introspection Framework v2.0 ***\n\n");
		printf("Usage:\n");
		printf("%s [-v] [-o logfile] [-s] [-d] [-h] <domain name>\n", argv[0]);
		printf("\t-v Increases verbosity of output logging, can be specified several times.\n");
		printf("\t-o Specifies file where output logging goes. Default is stderr.\n");
		printf("\t-s Run in silent mode - do not output events to brain.\n");
		printf("\t-d Periodically dump callback statistics to logging target.\n");
		printf("\t-h Print this message and quit.\n");
		printf("Notes:\n");
		printf("\tRekall profile must be registered in LibVMI profile.\n");
		return 1;
	}

	domu = argv [optind];

	if (logger_init(log_file, verbosity))
	{
		goto exit;
	}

	// Returns with VM suspended
	rc = nif_init (domu, (bool *) &gstate.nif_busy);
	if (rc)
	{
		goto exit;
	}

	rc = nvmi_main_init ();
	if (rc)
	{
		goto exit;
	}

	rc = comms_init();
	if (rc)
	{
		goto exit;
	}

	rc = set_instr_points_rekall();
	if (rc)
	{
		goto exit;
	}

	// Resumes the VM, but returns with it paused
	rc = nif_event_loop();
	if (rc)
	{
		goto exit;
	}

exit:
	close_handler (0);

	// Resumes VM
	nif_fini();

	nvmi_main_fini();
	comms_fini();
	nvmi_info ("Main completed");

	logger_fini();
	return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "linux"
 * End:
 */

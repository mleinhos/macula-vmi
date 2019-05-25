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

//#define EXPERIMENTAL_READ_USERMEM 1

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

	// VMI info
	addr_t task_name_ofs;
	addr_t task_pid_ofs;
	addr_t task_ppid_ofs;
	addr_t task_mm_ofs;
	addr_t mm_pgd_ofs;

	addr_t va_current_task;

	// Special-case breakpoints
	addr_t va_exit_mm;

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
logger_init (void)
{
	int rc = 0;

#if 1
	rc = clog_init_fd (CLOGGER_ID, fileno(stderr));
#else
	rc =  clog_init_path (CLOGGER_ID, NVMI_LOG_FILE);
#endif
	if (rc) {
		fprintf (stderr, "Logger initialization failure\n");
		goto exit;
	}
	(void) clog_set_level (CLOGGER_ID, CLOG_INFO);

	(void) clog_set_time_fmt (CLOGGER_ID, "");
	(void) clog_set_date_fmt (CLOGGER_ID, "");
exit:
	return rc;
}


static void
close_handler(int sig)
{
	clog_info (CLOG(CLOGGER_ID), "Received signal %d, shutting down", sig);
	gstate.interrupted = true;
	nif_stop();
}


static int
pre_gather_registers (vmi_instance_t vmi,
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
		clog_debug (CLOG(CLOGGER_ID), "syscall arg %d = %lx", i, regs->syscall_args[i]);
	}

	// Get the rest of the context too, for context lookup. Beware KPTI!!
#if defined(ARM64)
	status  = vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr0,  TTBR0,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr1,  TTBR1,  event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp,     SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp_el0, SP_EL0, event->vcpu_id);

	for (int i = 0; i < NUMBER_OF(x); ++i) {
		(void) vmi_get_vcpureg (vmi, &x[i], R0+i, event->vcpu_id);
		clog_info (CLOG(CLOGGER_ID), "R%d = 0x%lx", i, x[i]);
	}

	clog_info (CLOG(CLOGGER_ID), "Event: ttbr0 = 0x%lx", event->arm_regs->ttbr0);
	clog_info (CLOG(CLOGGER_ID), "Event: ttbr1 = 0x%lx", event->arm_regs->ttbr1);
	clog_info (CLOG(CLOGGER_ID), "Event: ttbcr = 0x%lx", event->arm_regs->ttbcr);
	clog_info (CLOG(CLOGGER_ID), "Event: cpsr  = 0x%lx", event->arm_regs->cpsr);

	clog_info (CLOG(CLOGGER_ID), "context: ttbr0   = %lx", regs->arch.arm64.ttbr0);
	clog_info (CLOG(CLOGGER_ID), "context: ttbr1   = %lx", regs->arch.arm64.ttbr1);
	clog_info (CLOG(CLOGGER_ID), "context: sp_el0  = %lx", regs->arch.arm64.sp_el0);
	clog_info (CLOG(CLOGGER_ID), "context: sp      = %lx", regs->arch.arm64.sp);

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

exit:
	return rc;
}


static void
deref_task_context (gpointer arg)
{
	nvmi_task_info_t * tinfo = (nvmi_task_info_t *) arg;
	atomic_t val = 	atomic_dec (&tinfo->refct);
	assert (val >= 0);

	if (0 == val) {
		clog_info (CLOG(CLOGGER_ID), "**** Process pid=%ld comm=%s destroyed ****",
			 tinfo->einfo.pid, tinfo->einfo.comm);
		g_slice_free (nvmi_task_info_t, tinfo);
	}
}

static int
get_current_task (vmi_instance_t vmi,
		  vmi_event_t * vmievent,
		  nvmi_registers_t * regs,
		  addr_t * task)
{
	int rc = 0;

#if defined(ARM64)
	// Fast: get current task_struct *
	*task = regs->arch.arm64.sp_el0;
#else
	// x86: slow
	// key = regs->arch.intel.sp & NVMI_KSTACK_MASK;
	// ^^^ too uncertain for a process identification ...
	status_t status = vmi_read_addr_va(vmi,
					   regs->arch.intel.gs_base + gstate.va_current_task,
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
build_task_context (vmi_instance_t vmi, nvmi_registers_t * regs, addr_t curr_task, nvmi_task_info_t ** tinfo)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	char * pname = NULL;
	addr_t task_mm = 0;
	addr_t mm_pgd = 0;

	*tinfo = g_slice_new0 (nvmi_task_info_t);

	// TODO: context lifetime is mismanaged -- fix it.
	atomic_inc (&(*tinfo)->refct);

#if defined(ARM64)
	(*tinfo)->kstack = regs->arch.arm64.sp & NVMI_KSTACK_MASK;
#else
	(*tinfo)->kstack = regs->arch.intel.sp & NVMI_KSTACK_MASK;
#endif
	(*tinfo)->p_task_struct = curr_task;

	status = vmi_read_32_va(vmi,
				curr_task + gstate.task_pid_ofs,
				0,
				(uint32_t *) &(*tinfo)->einfo.pid);
	if (VMI_FAILURE == status) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's pid at %" PRIx64 " + %lx",
			 (*tinfo)->p_task_struct, gstate.task_pid_ofs);
		goto exit;
	}

	pname = vmi_read_str_va (vmi,
				 (*tinfo)->p_task_struct + gstate.task_name_ofs,
				 0);
	if (NULL == pname) {
		rc = EFAULT;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read task's comm at %" PRIx64 " + %lx",
			 (*tinfo)->p_task_struct, gstate.task_name_ofs);
		goto exit;
	}

	strncpy ((*tinfo)->einfo.comm, pname, sizeof((*tinfo)->einfo.comm));
	free (pname);


	// Read current->mm
	status = vmi_read_addr_va (vmi, curr_task + gstate.task_mm_ofs, 0, &task_mm);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read current->mm");
		goto exit;
	}

	// Read current->mm->pgd
	status = vmi_read_addr_va (vmi, task_mm + gstate.mm_pgd_ofs, 0, &(*tinfo)->task_dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to read mm->pgd");
		goto exit;
	}

	clog_info (CLOG(CLOGGER_ID), "(task->mm->pgd: PID %d --> dtb %lx",
		 (uint32_t) (*tinfo)->einfo.pid,
		 (*tinfo)->task_dtb);

	// TODO: populate task_dtb via task->mm->pgd
	status = vmi_pid_to_dtb (vmi, (*tinfo)->einfo.pid, &(*tinfo)->task_dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID), "Failed to find page base for task, pid=%ld",
			 (*tinfo)->einfo.pid);
		goto exit;
	}
	clog_info (CLOG(CLOGGER_ID), "vmi_pid_to_dtb: PID %d --> dtb %lx",
		 (uint32_t) (*tinfo)->einfo.pid,
		 (*tinfo)->task_dtb);

exit:
	return rc;
}


/**
 * pre_gather_context()
 *
 * Gather system context on the initial callback for a syscall.
 */
static int
pre_gather_context (vmi_instance_t vmi,
		    vmi_event_t* vmievent,
		    nvmi_cb_info_t * cbi,
		    nvmi_event_t ** event)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	reg_t key = 0;
	addr_t curr_task = 0;
	nvmi_task_info_t * task = NULL;
	nvmi_event_t * evt = (nvmi_event_t *) g_slice_new0 (nvmi_event_t);
	int argct = (NULL == cbi ? 0 : cbi->argct);

	rc = pre_gather_registers (vmi, vmievent, &evt->r, argct);
	if (rc) {
		goto exit;
	}

	rc = get_current_task (vmi, vmievent, &evt->r, &curr_task);
	if (rc) {
		clog_warn (CLOG(CLOGGER_ID), "Context could not be found");
		goto exit;
	}

	// Look for key in gstate.context_lookup. If it isn't there,
	// then allocate new nvmi_task_info_t and populate it
	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)curr_task);
	if (NULL == task) {
		// build new context

		rc = build_task_context (vmi, &evt->r, curr_task, &task);
		if (rc) {
			goto exit;
		}
		// The system owns a reference. When the task dies, we remove it.
		atomic_inc (&task->refct);

		task->key = key;
		g_hash_table_insert (gstate.context_lookup, (gpointer)key, task);
		// The table owns a reference to the task context.
//		atomic_inc (&task->refct);
	}

	evt->task = task;

	evt->cbi   = cbi;
	*event = evt;

exit:
	return rc;
}


static char *
read_memory (vmi_instance_t vmi,
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

#if defined(EXPERIMENTAL_READ_USERMEM)
	// Actually try to pull the contents out of user memory

		// FIXME: fix user mem deref on ARM
	// TODO: clear out v2p cache prior to translation

	// use vmi_get_kernel_struct_offset, to find task->mm->pgd
	// ARM: vmi_pid_to_dtb broken
	// ARM: vmi_read is misdirected. dtb wrong?
	// recompile libvmi with VMI_DEBUG_PTLOOKUP enabled
/*
	status = vmi_pid_to_dtb (vmi, evt->task->einfo.pid, &dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_info (CLOG(CLOGGER_ID),"Error could get DTB for pid %ld", evt->task->einfo.pid);
		goto exit;
	}
*/
	dtb = evt->task->task_dtb;
	clog_info (CLOG(CLOGGER_ID), "PID %ld --> DTB %lx",
		 evt->task->einfo.pid, dtb);

	//vmi_v2pcache_flush (vmi, dtb);
	vmi_v2pcache_flush (vmi,  ~0ull);

	access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB,
				 .dtb = dtb,
				 // .dtb = evt->r.arch.arm64.ttbr1,
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

	clog_info (CLOG(CLOGGER_ID), "Read string '%s' from memory", buf);
//	str = strdup ("junk");
	str = strdup (buf);
	goto exit;
/*
#if defined(X86_64) // INTEL

#  if 1 // x86: works
	str = vmi_read_str_va (vmi, va, evt->task->einfo.pid);
	if (NULL == str) {
		clog_info (CLOG(CLOGGER_ID),"Error: could not read string at %" PRIx64 " in PID %lx",
			va, evt->task->einfo.pid);
		goto exit;
	}
#  endif

#  if 0 // x86: works
	status = vmi_pid_to_dtb (vmi, evt->task->einfo.pid, &dtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_info (CLOG(CLOGGER_ID),"Error could get DTB for pid %ld", evt->task->einfo.pid);
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
//		 str, va, evt->task->einfo.pid);

#else // ARM
#endif
*/

#else
	snprintf (buf, sizeof(buf), "*0x%" PRIx64, va);
	str = strdup (buf);
	goto exit;
#endif


exit:
//	return rc;
	return str;
}


/**
 * pre_instr_cb()
 *
 * Called at beginning of a syscall.
 * TODO: Shift as much of this work as possible to a worker thread.
 */
static void
pre_instr_cb (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;

	// arg / cbi tells us whether this is syscall or special event
	nvmi_cb_info_t * cbi = (nvmi_cb_info_t *) arg;
	nvmi_event_t * evt = NULL;

	// Ugly impl first: clean this up later
	assert (NULL == cbi ||
		cbi->argct <= NUMBER_OF(nvmi_syscall_arg_regs));

	rc = pre_gather_context (vmi, event, cbi, &evt);
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

		clog_debug (CLOG(CLOGGER_ID), "Syscall processing arg %d, val=%lx", i, val);

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
		case NVMI_ARG_TYPE_PVOID:
			break;
		case NVMI_ARG_TYPE_STR:

			buf = read_memory (vmi, evt, val, 0, 0);
			if (NULL == buf) {
				clog_warn (CLOG(CLOGGER_ID), "Failed to read str syscall arg");
				continue;
			}
			// Only worry about 1 dereferenced pointer, for now
			evt->mem_ofs[i] = 0;
			evt->arg_lens[i] = MIN(sizeof(evt->mem), strlen(buf));
			strncpy (evt->mem, buf, sizeof(evt->mem));
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

	if (evt->task->einfo.pid == gstate.killpid &&
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
post_instr_cb (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	printf ("Post: Hit breakpoint: %s", (const char*) arg);
}


static int
handle_special_instr_point (const char *name, addr_t kva)
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

		rc = nif_enable_monitor (kva, name, pre_instr_cb, post_instr_cb, cbi);
		if (rc) {
			clog_warn (CLOG(CLOGGER_ID), "Failed to add pg/bp for %s at %" PRIx64 "", name, kva);
			goto exit;
		}
	}

exit:

	return rc;
}

static int
handle_syscall (char *name, addr_t kva)
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

	if (strncmp (name, "sys_", 4))
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
		clog_warn (CLOG(CLOGGER_ID), "\tdynamically adding symbol %s: no template found", name);
		cbi = &nvmi_syscalls[nvmi_syscall_new++];
		cbi->cb_type = NVMI_CALLBACK_SYSCALL;
		cbi->enabled = true;
		strncpy (cbi->name, name, SYSCALL_MAX_NAME_LEN);
	}

	if (!cbi->enabled) {
		rc = ENOENT; // not quite right
		goto exit;
	}

	rc = nif_enable_monitor (kva, name, pre_instr_cb, post_instr_cb, cbi);
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

		rc = handle_special_instr_point (name, kva);
		if (0 == rc) { // success
			continue;
		} else if (ENOENT != rc) {
			// failure for reason other than line mismatch
			goto exit;
		}

		// Otherwise, try to match with a syscall
		rc = handle_syscall (name, kva);
		if (0 == rc) { // success
			continue;
		} else if (ENOENT != rc) {
			// failure for reason other than line mismatch
			goto exit;
		}
	} // while

	clog_warn (CLOG(CLOGGER_ID), "Found %d syscalls to monitor", gstate.act_calls);
	rc = 0;

exit:
	if (NULL != input_file) {
		fclose(input_file);
	}

	return rc;
}


static int
handle_special_event (nvmi_event_t * evt)
{
	int rc = 0;
	nvmi_cb_info_t * cbi = evt->cbi;

	assert (cbi);
	assert (cbi->cb_type == NVMI_CALLBACK_SPECIAL);

	clog_info (CLOG(CLOGGER_ID), "special event %s occurred", cbi->name);

	if (cbi == &nvmi_special_cbs[NVMI_DO_EXIT_IDX]) {
		// handle process destruction
		clog_info (CLOG(CLOGGER_ID), "exit of process pid %ld proc %s",
			 evt->task->einfo.pid, evt->task->einfo.comm);

		if (evt->task->einfo.pid == gstate.killpid) {
			clog_info (CLOG(CLOGGER_ID), "Kill of process pid=%d succeeded", gstate.killpid);
			gstate.killpid = KILL_PID_NONE;
		}

		// we'll never see that again....
		g_hash_table_remove (gstate.context_lookup, (gpointer) evt->task->key);
	}

//exit:
	return rc;
}


static int
handle_syscall_event (nvmi_event_t * evt)
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
			//clog_info (CLOG(CLOGGER_ID), "\targ %d: %s", i+1, str);
		}
			break;

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

		}
			break;
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
	snprintf (buf2, sizeof(buf2), ")	proc=%s	pid=%ld	 TTBR0=%" PRIx32 "	TTBR1=%" PRIx32 "",
		  evt->task->einfo.comm, evt->task->einfo.pid, evt->r.arch.arm64.ttbr0, evt->r.arch.arm64.ttbr1);
#else
	snprintf (buf2, sizeof(buf2), ")	proc=%s		pid=%ld		CR3=%" PRIx64 "",
		  evt->task->einfo.comm, evt->task->einfo.pid, evt->r.arch.intel.cr3);
#endif
	strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);

	rc = zmq_send (gstate.zmq_event_socket, buf, strlen(buf)+1, 0);
        if (rc < 0) {
		clog_warn (CLOG(CLOGGER_ID),"zmq_send() failed: %d", rc);
        }

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
	while (!gstate.interrupted) {
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
			rc = handle_special_event (evt);
			break;
		case NVMI_CALLBACK_SYSCALL:
			rc = handle_syscall_event (evt);
			break;
		default:
			break;
		}

		// destroy the event: TODO - fix refct mismanagement!!
		//		deref_task_context ((gpointer)&evt->task);
		//		__sync_fetch_and_sub (&evt->task->refct, 1);

		deref_task_context ((gpointer) evt->task);
		g_slice_free (nvmi_event_t, evt);
	} // while

exit:
	clog_info (CLOG(CLOGGER_ID), "Completed event consumer loop");
	zmq_close (gstate.zmq_event_socket);
	gstate.zmq_event_socket = NULL;
	return NULL;
}

static void
nvmi_main_fini (void)
{
	if (gstate.consumer_thread) {
		g_thread_join (gstate.consumer_thread);
	}
	clog_info (CLOG(CLOGGER_ID), "Consumer thread joined");

	// releasing queue causes event consumer to return
	if (gstate.event_queue) {
		g_async_queue_unref (gstate.event_queue);
	}
	clog_info (CLOG(CLOGGER_ID), "Event queue dereferenced");

	if (gstate.context_lookup) {
		g_hash_table_destroy (gstate.context_lookup);
	}
	clog_info (CLOG(CLOGGER_ID), "Context lookup table destroyed");

}

static int
nvmi_main_init (void)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	vmi_instance_t vmi;

	rc = nif_get_vmi (&vmi);
	if (rc) {
		goto exit;
	}

	gstate.killpid = KILL_PID_NONE;
	gstate.context_lookup = g_hash_table_new_full (NULL, // hash
						       NULL, // key equal
						       NULL, // key destroy
						       deref_task_context); // val destroy -- IMPLEMENT ME!

	status |= vmi_get_offset (vmi, "linux_name", &gstate.task_name_ofs);
	status |= vmi_get_offset (vmi, "linux_pid",  &gstate.task_pid_ofs);
	status |= vmi_get_kernel_struct_offset (vmi, "task_struct", "mm", &gstate.task_mm_ofs);
	status |= vmi_get_kernel_struct_offset (vmi, "mm_struct", "pgd", &gstate.mm_pgd_ofs);
	//status |= vmi_get_offset (vmi, "linux_ppid",  &gstate.task_ppid_ofs);

	if (VMI_FAILURE == status) {
		clog_warn (CLOG(CLOGGER_ID), "Failed to get offset");
		rc = EIO;
		goto exit;
	}
	assert (gstate.task_name_ofs &&
		gstate.task_pid_ofs  &&
		gstate.task_mm_ofs   &&
		gstate.mm_pgd_ofs );
/*
	status = vmi_translate_ksym2v(vmi, "exit_mmap", &gstate.va_exit_mmap);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_warn (CLOG(CLOGGER_ID),"Error could get the current_task offset.");
		goto exit;
	}
*/

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
    clog_info (CLOG(CLOGGER_ID), "Shutting down request socket");
    zmq_close (gstate.zmq_request_socket);
    gstate.zmq_request_socket = NULL;

    return NULL;
}

static void
comms_fini(void)
{
	if (gstate.zmq_context) {
		zmq_ctx_shutdown (gstate.zmq_context);
		zmq_ctx_destroy (gstate.zmq_context);
	}

	if (gstate.zmq_event_socket)  zmq_close (gstate.zmq_event_socket);
	if (gstate.zmq_request_socket)  zmq_close (gstate.zmq_request_socket);

	if (gstate.request_service_thread) {
		g_thread_join (gstate.request_service_thread);
	}

	gstate.zmq_context = NULL;
	gstate.zmq_event_socket  = NULL;
	gstate.zmq_request_socket  = NULL;
	clog_info (CLOG(CLOGGER_ID), "Comms shutdown");
}

static int
comms_init(void)
{
	int rc = 0;

	gstate.zmq_context = zmq_ctx_new();
	if (NULL == gstate.zmq_context) {
		rc = errno;
		clog_warn (CLOG(CLOGGER_ID), "zmq_ctx_new() failed");
		goto exit;
	}

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

	gstate.request_service_thread = g_thread_new ("request servicer", comms_request_servicer, NULL);

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

	if (argc != 3) {
		printf("Usage: %s <domain name> <path to system_map>\n", argv[0]);
		return 1;
	}

	if (logger_init()) {
		goto exit;
	}

	/* Handle ctrl+c properly */
	gstate.act.sa_handler = close_handler;
	gstate.act.sa_flags = 0;
	sigemptyset(&gstate.act.sa_mask);
	sigaction(SIGHUP,  &gstate.act, NULL);
	sigaction(SIGTERM, &gstate.act, NULL);
	sigaction(SIGINT,  &gstate.act, NULL);
	sigaction(SIGALRM, &gstate.act, NULL);

	// Returns with VM suspended
	rc = nif_init (argv[1]);
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

	rc = set_instrumentation_points (argv[2]);
	if (rc) {
		goto exit;
	}

	rc = nif_event_loop();
	if (rc) {
		goto exit;
	}

exit:
	gstate.interrupted = true;

	nif_stop();
	nif_fini();

	nvmi_main_fini();
	comms_fini();
	clog_info (CLOG(CLOGGER_ID), "Main completed");

	logger_fini();
	return rc;
}

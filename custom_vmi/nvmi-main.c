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

#include "nif-vmi-iface.h"
#include "nvmi-syscall-defs.h"
#include "process_kill_helper.h"
#include "nvmi-internal-defs.h"

#define NVMI_EVENT_QUEUE_TIMEOUT_uS (5 * 1000)

#define NVMI_KSTACK_MASK (~0x1fff) // 8k stack

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

typedef unsigned long atomic_t;

static inline atomic_t atomic_inc (atomic_t * val)
{
	return __sync_add_and_fetch (val, 1);
}

static inline atomic_t atomic_dec (atomic_t * val)
{
	return __sync_sub_and_fetch (val, 1);
}


static void
close_handler(int sig)
{
	gstate.interrupted = true;
	nif_stop();
}

/*
// Kills the current domU process by corrupting its state upon a
// syscall. May need further work.
//
// Reference linux kernel:
// arch/x86/entry/entry_64.S
// arch/arm64/kernel/entry.S

static void
linux_kill_curr_proc (vmi_instance_t vmi, vmi_event_t* event)
{
	// We're at the entry of a syscall.
	uint64_t stack[6] = {0};
	uint64_t sp_val = 0;
	status_t status = VMI_SUCCESS;
	size_t bytes_read = 0;
	static int call_ct = 0;

#ifdef ARM64
	// We may need to clobber X0 ... X5 for the ARM case
	reg_t regsp = SP_USR;
#else
	reg_t regsp = RSP;
#endif

//#ifdef ARM64
	status = vmi_set_vcpureg(vmi, 0, X0, event->vcpu_id);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write X0 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X1, event->vcpu_id);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write X1 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X2, event->vcpu_id);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write X2 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X3, event->vcpu_id);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write X3 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X4, event->vcpu_id);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write X4 register\n");
		goto exit;
	}
//#endif

exit:
	++call_ct;
	if (100 == call_ct) {
		gstate.killpid = KILL_PID_NONE;
	}
}
*/


static int
pre_gather_registers (vmi_instance_t vmi,
		      vmi_event_t* event,
		      nvmi_registers_t * regs,
		      int argct)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;

	for (int i = 0; i < argct; ++i) {
		status_t status = vmi_get_vcpureg (vmi,
						   &regs->syscall_args[i],
						   nvmi_syscall_arg_regs[i],
						   event->vcpu_id);
		if (VMI_FAILURE == status) {
			rc = EIO;
			goto exit;
		}
	}

	// Get the rest of the context too, for context lookup. Beware KPTI!!
#if defined(ARM64)
	status  = vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr0, TTBR0, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr1, TTBR1, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp,   SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp_el0, SP_EL0, event->vcpu_id);
	/*
	fprintf (stderr, "context: ttbr0   = %lx\n", regs->arch.arm64.ttbr0);
	fprintf (stderr, "context: ttbr1   = %lx\n", regs->arch.arm64.ttbr1);
	fprintf (stderr, "context: sp_el0  = %lx\n", regs->arch.arm64.sp_el0);
	fprintf (stderr, "context: sp      = %lx\n", regs->arch.arm64.sp);
	*/
#else
	status  = vmi_get_vcpureg (vmi, &regs->arch.intel.cr3, CR3,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.intel.sp,  RSP,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.intel.gs_base,  GS_BASE, event->vcpu_id);
#endif
	if (VMI_SUCCESS != status) {
		rc = EFAULT;
		fprintf (stderr, "vmi_get_vcpureg() failed\n");
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
		fprintf (stderr, "**** Process pid=%ld comm=%s destroyed ****\n",
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
		fprintf (stderr, "Failed to determine current task (from gs_base + curr_task_offset)\n");
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
		fprintf (stderr, "Failed to read task's pid at %" PRIx64 " + %lx\n",
			 (*tinfo)->p_task_struct, gstate.task_pid_ofs);
		goto exit;
	}

	pname = vmi_read_str_va (vmi, 
				 (*tinfo)->p_task_struct + gstate.task_name_ofs,
				 0);
	if (NULL == pname) {
		rc = EFAULT;
		fprintf (stderr, "Failed to read task's comm at %" PRIx64 " + %lx\n",
			 (*tinfo)->p_task_struct, gstate.task_name_ofs);
		goto exit;
	}

	strncpy ((*tinfo)->einfo.comm, pname, sizeof((*tinfo)->einfo.comm));
	free (pname);
/*
	status = vmi_pid_to_dtb (vmi, (*tinfo)->einfo.pid, &(*tinfo)->updb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		fprintf (stderr, "Failed to find page base for task, pid=%ld\n",
			 (*tinfo)->einfo.pid);
		goto exit;
	}
*/

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
		fprintf (stderr, "Context could not be found\n");
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
	addr_t pdb = 0;

#if defined(X86_64)

#  if 1 // x86: works
	str = vmi_read_str_va (vmi, va, evt->task->einfo.pid);
	if (NULL == str) {
		fprintf(stderr, "Error: could not read string at %" PRIx64 " in PID %lx\n",
			va, evt->task->einfo.pid);
		goto exit;
	}
#  endif

#  if 0 // x86: works
	status = vmi_pid_to_dtb (vmi, evt->task->einfo.pid, &pdb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		fprintf(stderr, "Error could get PDB for pid %ld\n", evt->task->einfo.pid);
		goto exit;
	}
	
	access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB,
				 .dtb = pdb,
/*
  #if defined(ARM64)
  .dtb = evt->r.arch.arm64.ttbr1,
  #else
  .dtb = evt->r.arch.intel.updb,
  #endif
*/
				 .addr = va };
	// better to read directly into caller buffer

	str = vmi_read_str(vmi, &ctx);
//	if (VMI_FAILURE == status) {
	if (NULL == str) {
		rc = EIO;
		fprintf(stderr, "Error could get PA from VA %" PRIx64 ".\n", va);
		goto exit;
	}
//	status = vmi_pagetable_lookup (vmi, evt->r.ttrb1, va, &pa);
//	status = vmi_read_va (vmi, va, evt->r.ttbr1)
#  endif
	
	fprintf (stderr, "Successfully read string '%s' from mem (%lx pid %lx)\n",
		 str, va, evt->task->einfo.pid);
	
#else
	// FIXME: fix user mem deref on ARM
	// TODO: clear out v2p cache prior to translation
	str = strdup("<string value>");
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

	//fprintf (stderr, "PRE: syscall: %s pid=%ld comm=%s \n",
	//cbi->name, evt->task->einfo.pid, evt->task->einfo.comm);
	
	for (int i = 0; i < cbi->argct; ++i) {
		reg_t val = evt->r.syscall_args[i];
		char * buf = NULL;

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
			break;
		case NVMI_ARG_TYPE_STR:
			buf = read_memory (vmi, evt, val, 0, 0);
			if (NULL == buf) {
				fprintf (stderr, "Failed to read str syscall arg\n");
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
				fprintf (stderr, "Failed to read addrinfo struct\n");
				continue;
			}

			rc = getaddrinfo (NULL, NULL, (const struct addrinfo *) &ai, &res);
			if (rc) {
				fprintf (stderr, "Failed to decode addrinfo struct\n");
				continue;
			}

			printf ("\targ %d: %s\n", i, res->ai_cannonname);
			freeaddrinfo (res);
			break;
#endif
		}
		default:
			break;
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
	printf ("Post: Hit breakpoint: %s\n", (const char*) arg);
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
			fprintf (stderr, "Failed to add pg/bp for %s at %" PRIx64 "\n", name, kva);
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
	gstate.act_calls++;
	if (gstate.act_calls == NVMI_MAX_SYSCALL_CT-1) { // max syscalls that we want to monitor
		rc = ENOSPC;
		fprintf (stderr, "Exceeding max allowed syscalls. Halting search.\n");
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
	fprintf (stderr, "#%d: Monitoring symbol %s at %" PRIx64 "\n",
		 gstate.act_calls, name, kva);

	// Stage syscall dynamically; name only
	if (NULL == cbi) {
		fprintf (stderr, "\tdynamically adding symbol %s: no template found\n", name);
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
		fprintf (stderr, "Failed to add pg/bp for %s at %" PRIx64 "\n", name, kva);
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
		fprintf (stderr, "Can't open system map file '%s'\n", mappath);
		goto exit;
	}

	while (fgets( one_line, sizeof(one_line), input_file) != NULL) {
		char * name = NULL;
		addr_t kva = 0;

		// sample line: "ffffffff81033570 T sys_mmap\n"
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

	fprintf (stderr, "Found %d syscalls to monitor\n", gstate.act_calls);
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

	fprintf (stderr, "special event %s occurred\n", cbi->name);

	if (cbi == &nvmi_special_cbs[NVMI_DO_EXIT_IDX]) {
		// handle process destruction
		fprintf (stderr, "exit of process pid %ld proc %s\n",
			 evt->task->einfo.pid, evt->task->einfo.comm);

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

//	fprintf (stderr, "syscall %s pid %ld proc %s\n",
//		 cbi->name, evt->task->einfo.pid, evt->task->einfo.comm);

	for (int i = 0; i < cbi->argct; ++i) {
		reg_t val = evt->r.syscall_args[i];
		//char * buf = NULL;

		switch (cbi->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
			//fprintf (stderr, "\targ %d: %lx\n", i+1, val);
			snprintf (buf2, sizeof(buf2), " %lx,", val);
			strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);
			break;
		case NVMI_ARG_TYPE_STR: // char *
		{
			const char * str = (const char *) &(evt->mem[ evt->mem_ofs[i]]);
			if (strlen(str) > 0) {
				snprintf (buf2, sizeof(buf2) - 1, " \"%s\",", str);
				strncat (buf, buf2, sizeof(buf) - strlen(buf) - 1);
			}
			//fprintf (stderr, "\targ %d: %s\n", i+1, str);
		}
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
				fprintf (stderr, "Failed to read addrinfo struct\n");
				continue;
			}

			rc = getaddrinfo (NULL, NULL, (const struct addrinfo *) &ai, &res);
			if (rc) {
				fprintf (stderr, "Failed to decode addrinfo struct\n");
				continue;
			}

			//printf ("\targ %d: %s\n", i+1, res->ai_cannonname);
			freeaddrinfo (res);
#endif
		}
			break;
		default:
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
		fprintf(stderr, "zmq_send() failed: %d\n", rc);
        }

	fprintf (stderr, "%s\n", buf);

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

	fprintf (stderr, "Begining event consumer loop\n");
	g_async_queue_ref (gstate.event_queue); 

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
	g_async_queue_unref (gstate.event_queue); 
	return NULL;
}

static void
nvmi_main_fini (void)
{
	if (gstate.consumer_thread) {
		g_thread_join (gstate.consumer_thread);
	}
	if (gstate.context_lookup) {
		g_hash_table_destroy (gstate.context_lookup);
	}
	if (gstate.event_queue) {
		g_async_queue_unref (gstate.event_queue);
	}
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
	//status |= vmi_get_offset (vmi, "linux_ppid",  &gstate.task_ppid_ofs);
	
	if (VMI_FAILURE == status) {
		fprintf (stderr, "Failed to get offset\n");
		rc = EIO;
		goto exit;
	}
	assert (gstate.task_name_ofs &&
		gstate.task_pid_ofs   );
/*
	status = vmi_translate_ksym2v(vmi, "exit_mmap", &gstate.va_exit_mmap);
	if (VMI_FAILURE == status) {
		rc = EIO;
		fprintf(stderr, "Error could get the current_task offset.\n");
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
		fprintf(stderr, "Error could get the current_task offset.\n");
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

    void* subscriber = zmq_socket (gstate.zmq_context, ZMQ_PAIR);
    if (NULL == subscriber) {
        rc = zmq_errno();
        fprintf(stderr, "zmq_socket() failed");
        goto exit;
    }

    zmq_connect (subscriber, ZMQ_REQUEST_CHANNEL);

    while (!gstate.interrupted) {
        char msg[30] = {0};
        vmi_pid_t pid = -1;

	rc = zmq_recv (subscriber, msg, sizeof(msg), 0);
        if (rc <= 0) {
            fprintf (stderr, "Received empty string. All done.\n");
            break;
        }
    
        //
        // Set global killpid: now syscall hook will watch for this pid
        //

        pid = *(vmi_pid_t*) msg;
        printf ("received raw pid --> %d\n", pid);

        gstate.killpid = pid;

        //free (str);
    }

exit:
    return NULL;
}

static void
comms_fini(void)
{
	if (gstate.zmq_event_socket)  zmq_close (gstate.zmq_event_socket);
	if (gstate.zmq_context) zmq_ctx_destroy (gstate.zmq_context);

	if (gstate.request_service_thread) {
		g_thread_join (gstate.request_service_thread);
	}

	if (gstate.zmq_request_socket)  zmq_close (gstate.zmq_request_socket);

	gstate.zmq_context = NULL;
	gstate.zmq_event_socket  = NULL;
	gstate.zmq_request_socket  = NULL;
}

static int
comms_init(void)
{
	int rc = 0;

	gstate.zmq_context = zmq_ctx_new();
	if (NULL == gstate.zmq_context) {
		rc = errno;
		fprintf(stderr, "zmq_ctx_new() failed\n");
		goto exit;
	}

	gstate.zmq_event_socket = zmq_socket (gstate.zmq_context, ZMQ_PAIR);
	if (NULL == gstate.zmq_event_socket) {
		rc = zmq_errno();
		fprintf(stderr, "zmq_socket() failed");
		goto exit;
	}

	rc = zmq_bind (gstate.zmq_event_socket, ZMQ_EVENT_CHANNEL);
	if (rc) {
		fprintf (stderr, "zmq_connect(" ZMQ_EVENT_CHANNEL ") failed: %d\n", rc);
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

	/* Handle ctrl+c properly */
	gstate.act.sa_handler = close_handler;
	gstate.act.sa_flags = 0;
	sigemptyset(&gstate.act.sa_mask);
	sigaction(SIGHUP,  &gstate.act, NULL);
	sigaction(SIGTERM, &gstate.act, NULL);
	sigaction(SIGINT,  &gstate.act, NULL);
	sigaction(SIGALRM, &gstate.act, NULL);

	rc = comms_init();
	if (rc) {
		goto exit;
	}

	// Returns with VM suspended
	rc = nif_init (argv[1]);
	if (rc) {
		goto exit;
	}

	rc = nvmi_main_init ();
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

	return rc;
}

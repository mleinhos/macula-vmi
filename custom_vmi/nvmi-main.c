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

#include "nif-vmi-iface.h"
#include "nvmi-syscall-defs.h"
#include "process_kill_helper.h"
#include "nvmi-internal-defs.h"

#define NVMI_EVENT_QUEUE_TIMEOUT_uS (5 * 1000)


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

	// Maps easy value to process context, e.g. curent
	// task_struct, or base kernel stack pointer.
	GHashTable * context_lookup;

	GThread * consumer_thread;
	GAsyncQueue * event_queue;
	
} nvmi_state_t;

static nvmi_state_t gstate = {0};


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
		status_t status = vmi_get_vcpureg (vmi, &regs->syscall_args[i], nvmi_syscall_arg_regs[i], event->vcpu_id);
		if (VMI_FAILURE == status) {
			rc = EIO;
			goto exit;
		}
	}

	// Get the rest of the context too, for context lookup
#if defined(ARM64)
	status  = vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr0, TTBR0, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.ttbr1, TTBR1, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp,   SP_USR, event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp_el0, SP_EL0, event->vcpu_id);

#else
	status  = vmi_get_vcpureg (vmi, &regs->arch.intel.cr3, CR3,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.intel.sp,  RSP,     event->vcpu_id);
	status |= vmi_get_vcpureg (vmi, &regs->arch.intel.gs,  GS_BASE, event->vcpu_id);
#endif
	if (VMI_SUCCESS != status) {
		rc = EFAULT;
		fprintf (stderr, "vmi_get_vcpureg() failed\n");
		goto exit;
	}

exit:
	return rc;
}

#if !defined(ARM64)
//#if defined(X86_64) || defined(I386)
static int
get_current_task (vmi_instance_t vmi, reg_t gs_base, addr_t * task)
{
	int rc = 0;
	status_t status;

	status = vmi_read_addr_va(vmi,
				  gs_base + gstate.va_current_task,
	                          0,
				  task);
	if (VMI_SUCCESS != status) {
		rc = EIO;
		task = NULL;
		fprintf (stderr, "Fast try: Fail to read anything at base+curr_task_offset\n");
		goto exit;
	}

exit:
	return rc;
}
#endif

static void
deref_task_context (gpointer arg)
{
	nvmi_task_info_t * tinfo = (nvmi_task_info_t *) arg;
	int val = __sync_fetch_and_sub (&tinfo->refct, 1);

	assert (val >= 0);

	if (0 == val) {
		g_slice_free (nvmi_task_info_t, tinfo);
	}
}

static int
build_task_context (vmi_instance_t vmi, nvmi_registers_t * regs, nvmi_task_info_t ** tinfo)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	char * pname = NULL;

	*tinfo = g_slice_new0 (nvmi_task_info_t);

#if defined(ARM64)
	(*tinfo)->p_task_struct = regs->arch.arm64.sp_el0;
	(*tinfo)->kstack        = regs->arch.arm64.sp & ~0x3ff; // ??
#else
	(*tinfo)->kstack = regs->arch.intel.sp & ~0x3fff;

	rc = get_current_task (vmi, regs->arch.intel.gs, &(*tinfo)->p_task_struct);
	if (rc) {
		goto exit;
	}
#endif
	status = vmi_read_32_va(vmi,
				(*tinfo)->p_task_struct + gstate.task_pid_ofs,
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

	// Take a reference for the guest process that "owns" this
	// data. Once the process dies, remove that reference.
	__sync_fetch_and_add (&(*tinfo)->refct, 1);

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
		    nvmi_syscall_def_t * sc,
		    nvmi_event_t ** event)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	reg_t key = 0;
	nvmi_task_info_t * task = NULL;
	nvmi_event_t * evt = (nvmi_event_t *) g_slice_new0 (nvmi_event_t);
	int argct = (NULL == sc ? 0 : sc->argct);
	
	rc = pre_gather_registers (vmi, vmievent, &evt->r, argct);
	if (rc) {
		goto exit;
	}

#if defined(ARM64)
	key = evt->r.arch.arm64.sp_el0;
//	status = vmi_get_vcpureg (vmi, &key, SP_EL0, event->vcpu_id);
#else
//	status = vmi_get_vcpureg (vmi, &key, RSP, event->vcpu_id);
//	key &= ~0x3fff; // base of 16k stack
	key = evt->r.arch.intel.sp & ~0x3fff;
#endif

	// look for key in gstate.context_lookup. If it isn't there,
	// then allocate new nvmi_task_info_t and populate it
	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)key);
	if (NULL == task) {
		// build new context
		rc = build_task_context (vmi, &evt->r, &task);
		if (rc) {
			goto exit;
		}

		// hash table holds a reference ??
		//__sync_fetch_and_add (&task->refct, 1);
		g_hash_table_insert (gstate.context_lookup, (gpointer)key, task);
	}

	evt->task = task;
	evt->sc   = sc;
	*event = evt;

exit:
	return rc;
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
	nvmi_syscall_def_t * sc = (nvmi_syscall_def_t *) arg;
	nvmi_event_t * evt = NULL;

	// Ugly impl first: clean this up later
	fprintf (stderr, "%s:%d\n", __FUNCTION__, __LINE__);

	assert (NULL == sc ||
		sc->argct <= NUMBER_OF(nvmi_syscall_arg_regs));

	rc = pre_gather_context (vmi, event, sc, &evt);
	if (rc) {
		goto exit;
	}

	if (NULL == sc) {
		// We don't have any metadata on this syscall
		goto exit;
	}

	fprintf (stderr, "PRE: syscall: %s pid=%ld comm=%s \n",
		sc->name, evt->task->einfo.pid, evt->task->einfo.comm);
	
	for (int i = 0; i < sc->argct; ++i) {
		reg_t val = evt->r.syscall_args[i];
		char * buf = NULL;

		switch (sc->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
//			printf ("\targ %d: %lx\n", i, val);
			break;
		case NVMI_ARG_TYPE_STR:
			buf = vmi_read_str_va (vmi,
					       val,
					       evt->task->einfo.pid);
			if (NULL == buf) {
				fprintf (stderr, "Failed to read str syscall arg\n");
				continue;
			}

			// Only worry about 1 dereferenced pointer, for now
			evt->mem_ofs[i] = 0;
			evt->arg_lens[i] = MIN(sizeof(evt->mem), strlen(buf));
			strncpy (evt->mem, buf, sizeof(evt->mem));
			
//			printf ("\targ %d: %s\n", i, buf);
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

//	__sync_fetch_and_add (&evt->task->refct, 1);
	g_async_queue_push (gstate.event_queue, (gpointer) evt);

exit:
	return;
}


static void
post_instr_cb (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	printf ("Post: Hit breakpoint: %s\n", (const char*) arg);
}

// TODO: move to rekall
// TODO: handle KASLR
static int
set_instrumentation_points (const char* mappath)
{
	FILE* input_file = NULL;
	char* name = NULL;
	char one_line[1024];
	char* nl = NULL;
	int rc = 0;
	addr_t sys_va;
	nvmi_syscall_def_t * sc = NULL;
	size_t nvmi_syscall_new = 0; // where to put new (incomplete) entries into table?

	input_file = fopen(mappath, "r+");
	if (NULL == input_file) {
		rc = EINVAL;
		fprintf (stderr, "Can't open system map file '%s'\n", mappath);
		goto exit;
	}

	for (int i = 0; i < NUMBER_OF(nvmi_syscalls); ++i) {
		if (strlen(nvmi_syscalls[i].name) > 0) {
			++nvmi_syscall_new;
		}
	}
	
	while (fgets( one_line, 1000, input_file) != NULL) {
		if (NULL == (name = strstr(one_line, " T "))) { //find the global text section symbols
			//printf("\nDidn't find any text symbol");
			continue;
		}

		// Doing this coz case insensitive function was behaving weirdly
		if ((NULL == strstr(one_line, " sys_")) &&
		    (NULL == strstr(one_line, " SyS_")) &&
		    (NULL == strstr(one_line, " Sys_")))
		{
			continue;
		}

		// Skip these symbols: they are not syscalls
		if (!strcmp(&name[4], "call_table") ||
		    !strncmp(&name[4], "dmi", 3)              ||
		    !strcmp(&name[4],  "tz")                  || /* used by gettimeofday */
		    !strcmp(&name[4],  "tracepoint_refcount") ||
		    !strcmp(&name[4],  "table")               ||
		    !strcmp(&name[4],  "perf_refcount_enter") ||
		    !strcmp(&name[4],  "perf_refcount_exit")  ||
		    !strcmp(&name[4], "reg_genericv8_init")    ) {
			continue;
		}
		
		*name = '\0';
		sys_va = (addr_t) strtoul(one_line, NULL, 16);

		name = name + 3;
		if (NULL != (nl =strchr(name, '\n')))
			*nl='\0';
		
		sc = NULL;
		// We've found a syscall, and we have its address. Now, find it in our syscall table
		for (int i = 0; i < nvmi_syscall_new; ++i) { //NUMBER_OF(nvmi_syscalls); ++i) {
			if (!strcmp(&name[4], nvmi_syscalls[i].name)) {
				sc = &nvmi_syscalls[i];
				break;
			}
		}

		// Now, with or without the syscall def, monitor this syscall
		fprintf (stderr, "#%d: Monitoring syscall %s at %" PRIx64 "\n",
			 gstate.act_calls, name, sys_va);
		// Stage syscall dynamically; name only
		if (NULL == sc) {
			fprintf (stderr, "\tdynamically adding syscall %s: no template found\n", name);
			sc = &nvmi_syscalls[nvmi_syscall_new++];
			sc->enabled = true;
			strncpy (sc->name, name, NVMI_MAX_SYSCALL_NAME_LEN);
		}

		if (!sc->enabled) {
			continue;
		}
		
		rc = nif_enable_monitor (sys_va, name, pre_instr_cb, post_instr_cb, sc);//&nvmi_syscalls[i]);
		if (rc) {
			fprintf (stderr, "Failed to add pg/bp for %s at %" PRIx64 "\n", name, sys_va);
			goto exit;
		}

		gstate.act_calls++;
		if (gstate.act_calls == NVMI_MAX_SYSCALL_CT-1) { // max syscalls that we want to monitor
			fprintf (stderr, "Exceeding max allowed syscalls. halting search.\n");
			break;
		}
	} // while

	fprintf (stderr, "Found %d syscalls to monitor\n", gstate.act_calls);
exit:
	if (NULL != input_file) {
		fclose(input_file);
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
	nvmi_syscall_def_t * sc = NULL;

	int rc = 0;

	fprintf (stderr, "Begining event consumer loop\n");
	g_async_queue_ref (gstate.event_queue); 

	// Monitor gstate.interrupted
	while (true) {
		nvmi_event_t * evt = (nvmi_event_t *)
			g_async_queue_timeout_pop (gstate.event_queue, NVMI_EVENT_QUEUE_TIMEOUT_uS);
		if (NULL == evt) {
			// Nothing in queue. Is it time to return yet?
			if (!gstate.interrupted) {
				continue;
			}
			// otherwise, give up!
			goto exit;
		}

		// Process the event
		assert (evt);
		assert (evt->sc);

		sc = evt->sc;

		fprintf (stderr, "syscall %s pid %ld proc %s\n",
			 sc->name, evt->task->einfo.pid, evt->task->einfo.comm);

		for (int i = 0; i < sc->argct; ++i) {
			reg_t val = evt->r.syscall_args[i];
			char * buf = NULL;

			switch (sc->args[i].type) {
			case NVMI_ARG_TYPE_SCALAR:
				fprintf (stderr, "\targ %d: %lx\n", i+1, val);
				break;
			case NVMI_ARG_TYPE_STR: // char *
				fprintf (stderr, "\targ %d: %s\n", i+1, (char *) &(evt->mem[ evt->mem_ofs[i]] ));
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

				printf ("\targ %d: %s\n", i+1, res->ai_cannonname);
				freeaddrinfo (res);
#endif
			}
				break;
			default:
				break;
			} // switch
		} // for

		// destroy the event: TODO - fix refct mismanagement!!

//		deref_task_context ((gpointer)&evt->task);

//		__sync_fetch_and_sub (&evt->task->refct, 1);

		g_slice_free (nvmi_event_t, evt);
	}

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
						       NULL); // val destroy -- IMPLEMENT ME!
	
	status |= vmi_get_offset (vmi, "linux_name", &gstate.task_name_ofs);
	status |= vmi_get_offset (vmi, "linux_pid",  &gstate.task_pid_ofs);
//	status |= vmi_get_offset (vmi, "linux_ppid",  &gstate.task_ppid_ofs);
	
	if (VMI_FAILURE == status) {
		fprintf (stderr, "Failed to get offset\n");
		rc = EIO;
		goto exit;
	}
	assert (gstate.task_name_ofs &&
		gstate.task_pid_ofs   );

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

//	rc = comms_init();
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
//	comms_fini();

	return rc;
}

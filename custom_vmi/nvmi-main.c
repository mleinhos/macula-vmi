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
	// task_struct, or base kernel stack pointer
	GHashTable * context_lookup;

	
} nvmi_state_t;

static nvmi_state_t gstate = {0};


static void
close_handler(int sig)
{
	gstate.interrupted;
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
	status |= vmi_get_vcpureg (vmi, &regs->arch.arm64.sp,    TTBR0, event->vcpu_id);

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
		printf("\nFast try: Fail to read anything at base+curr_task_offset");
		goto exit;
	}

exit:
	return rc;
}
#endif

static int
build_task_context (vmi_instance_t vmi, nvmi_registers_t * regs, nvmi_task_info_t ** tinfo)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	char * pname = NULL;

	*tinfo = g_malloc0 (sizeof(nvmi_task_info_t));

#if defined(ARM64)
	(*tinfo)->p_task_struct = regs->arch.arm64.sp_el0;
	(*tinfo)->kstack        = regs->arch.arm64.sp & ~0x3ff;
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
				(uint32_t *) &(*tinfo)->pid);
	if (VMI_FAILURE == status) {
		rc = EFAULT;
		fprintf (stderr, "Failed to read task's pid\n");
		goto exit;
	}

	pname = vmi_read_str_va (vmi, 
				 (*tinfo)->p_task_struct + gstate.task_name_ofs,
				 0);
	if (NULL == pname) {
		rc = EFAULT;
		fprintf (stderr, "Failed to read task's comm value\n");
		goto exit;
	}

	strncpy ((*tinfo)->comm, pname, sizeof((*tinfo)->comm));
	free (pname);

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
		    vmi_event_t* event,
		    nvmi_syscall_def_t * sc,
		    nvmi_event_context_t ** event_context)
{
	int rc = 0;
	status_t status = VMI_SUCCESS;
	reg_t key = 0;
	nvmi_task_info_t * task = NULL;
	nvmi_event_context_t * ctx = (nvmi_event_context_t *) g_malloc0 (sizeof(nvmi_event_context_t));
	
	rc = pre_gather_registers (vmi, event, &ctx->r, sc->argct);
	if (rc) {
		goto exit;
	}

#if defined(ARM64)
	key = ctx->r.arch.arm64.sp_el0;
//	status = vmi_get_vcpureg (vmi, &key, SP_EL0, event->vcpu_id);
#else
//	status = vmi_get_vcpureg (vmi, &key, RSP, event->vcpu_id);
//	key &= ~0x3fff; // base of 16k stack
	key = ctx->r.arch.intel.sp & ~0x3fff;
#endif

	// look for key in gstate.context_lookup. If it isn't there,
	// then allocate new nvmi_task_info_t and populate it
	task = g_hash_table_lookup (gstate.context_lookup, (gpointer)key);
	if (NULL == task) {
		// build new context
		rc = build_task_context (vmi, &ctx->r, &task);
		if (rc) {
			goto exit;
		}

		g_hash_table_insert (gstate.context_lookup, (gpointer)key, task);
	}

	ctx->task = task;
	*event_context = ctx;

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
	nvmi_event_context_t * ectx = NULL;

	// Ugly impl first: clean this up later
	assert (sc->argct <= NUMBER_OF(nvmi_syscall_arg_regs));
	rc = pre_gather_context (vmi, event, sc, &ectx);
	if (rc) {
		goto exit;
	}

	printf ("PRE: syscall: %s pid=%d comm=%s \n",
		sc->name, ectx->task->pid, ectx->task->comm);

	for (int i = 0; i < sc->argct; ++i) {
		reg_t val = ectx->r.syscall_args[i];
		char * buf = NULL;

		switch (sc->args[i].type) {
		case NVMI_ARG_TYPE_SCALAR:
			printf ("\targ %d: %lx\n", i, val);
			break;
		case NVMI_ARG_TYPE_STR:
			buf = vmi_read_str_va (vmi,
					       val,
					       ectx->task->pid);
			if (NULL == buf) {
				fprintf (stderr, "Failed to read str syscall arg\n");
				continue;
			}
			printf ("\targ %d: %s\n", i, buf);
			free (buf);
			break;
		case NVMI_ARG_TYPE_SA: {
#if 0
			struct addrinfo_in6 ai;
			struct addrinfo *res;

			status = vmi_read_va (vmi,
					      val,
					      ectx->task->pid,
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
	bool found = false;

	input_file = fopen(mappath, "r+");

	if (NULL == input_file) {
		rc = EINVAL;
		printf("\nCant open system map file\n");
		goto exit;
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

		*name = '\0';
		sys_va = (addr_t) strtoul(one_line, NULL, 16);

		name = name + 3;
		if (NULL != (nl =strchr(name, '\n')))
			*nl='\0';

		found = false;
		// We've found a syscall, and we have its address. Now, find it in our syscall table
		for (int i = 0; i < NUMBER_OF(nvmi_syscalls); ++i) {
			if (!strcmp(&name[4], nvmi_syscalls[i].name)) {
				found = true;
				fprintf (stderr, "Monitoring syscall %s\n", name);
				rc = nif_enable_monitor (sys_va, name, pre_instr_cb, post_instr_cb, &nvmi_syscalls[i]);
				if (rc) {
					printf("Failed to add pg/bp for %s at %" PRIx64 "\n", name, sys_va);
					goto exit;
				}

				gstate.act_calls++;

				if (gstate.act_calls == MAX_CALLS-1) { // max syscalls that we want to monitor
					goto exit;
				}
			}
		}

		if (!found) {
			fprintf (stderr, "Found syscall %s but not monitoring it\n", name);
		}
	}

exit:
	if (NULL != input_file) {
		fclose(input_file);
	}

	return rc;
}

void
nvmi_main_fini (void)
{
	g_hash_table_destroy (gstate.context_lookup);
}


int
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
	gstate.context_lookup = g_hash_table_new (NULL, NULL);
	
	status |= vmi_get_offset (vmi, "linux_name", &gstate.task_name_ofs);
	status |= vmi_get_offset (vmi, "linux_pid",  &gstate.task_pid_ofs);
//	status |= vmi_get_offset (vmi, "linux_ppid",  &gstate.task_ppid_ofs);
	
	if (VMI_FAILURE == status) {
		fprintf (stderr, "Failed to get offset\n");
		rc = EIO;
		goto exit;
	}


	status = vmi_translate_ksym2v(vmi, "per_cpu__current_task", &gstate.va_current_task);
	if (VMI_FAILURE == status) {
		status = vmi_translate_ksym2v(vmi, "current_task", &gstate.va_current_task);
	}

	if (VMI_FAILURE == status) {
		fprintf(stderr, "Fast try: Error could get the current_task offset.\n");
		rc = EIO;
		goto exit;
	}

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
	nif_stop();
	nif_fini();
	nvmi_main_fini();
//	comms_fini();
}

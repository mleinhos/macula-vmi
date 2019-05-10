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
#include "nvmi.h"
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

#include "nif-vmi-iface.h"
#include "process_kill_helper.h"

static vmi_pid_t killpid = KILL_PID_NONE;
static int act_calls = 0;


/* Signal handler */
static struct sigaction act;
static int interrupted = 0;

static void
close_handler(int sig)
{
	nif_stop();
}


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
		killpid = KILL_PID_NONE;
	}
}


/**
 * pre_gather_context()
 *
 * Gather system context on the initial callback for a syscall.
 */
static int
pre_gather_context (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	int rc = 0;

	
exit:
	return rc;
}

/**
 * pre_instr_cb()
 *
 * Called at beginning of a syscall.
 */
static void
pre_instr_cb (vmi_instance_t vmi, vmi_event_t* event, void* arg)
{
	printf ("Pre: Hit breakpoint: %s\n", (const char*) arg);
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

		//Doing this coz case insensitive function was behaving weirdly
		if (NULL==strstr(one_line, " sys_")) {
			if (NULL==strstr(one_line, " SyS_")) {
				if (NULL==strstr(one_line, " Sys_")) { //possible sys_call
					//printf("\nFound text_sec but didn't find any sys_call symbol in %s", one_line);
					continue;
				}
			}//second if
		}//first if

		*name = '\0';
		sys_va = (addr_t) strtoul(one_line, NULL, 16);

		name = name + 3;
		if (NULL != (nl =strchr(name, '\n')))
			*nl='\0';

		//printf("\nAddress Extracted: %s Address Converted: %" PRIx64 " Backup Inst: %" PRIx32 "\n", one_line, sys_va, backup_smc1);
		rc = nif_enable_monitor (sys_va, name, pre_instr_cb, post_instr_cb, strdup(name));
		if (rc) {
			printf("Failed to add pg/bp for %s at %" PRIx64 "\n", name, sys_va);
			goto exit;
		}

		act_calls++;

		if (act_calls == MAX_CALLS-1) //max syscalls that we want to monitor
			break;
	}

exit:
	if (NULL != input_file) {
		fclose(input_file);
	}

	return rc;
}

int
main (int argc, char* argv[])
{
	int rc = 0;
	status_t status;
	const char* name = argv[1];
	const char* in_path = argv[2];
	nif_xen_monitor xa;
	vmi_event_t trap_event, mem_event, cr3_event;

	if (argc != 3) {
		printf("Usage: %s <domain name> <path to system_map>\n", argv[0]);
		return 1;
	}

	/* Handle ctrl+c properly */
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);

//	rc = comms_init();
	if (rc) {
		goto exit;
	}

	// Returns with VM suspended
	rc = nif_init (argv[1]);
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
//	comms_fini();
}

/**
 * Description: Main driver for Ninspector. Uses libvmi, rekall, and
 *              nvmi-iface
 *
 * Company: Numen Inc.
 *
 * Developerd: Ali Islam
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

#include "process_kill_helper.h"

/* Signal handler */
static struct sigaction act;
static int interrupted = 0;

static void close_handler(int sig)
{
	int rc = 0;

	if (SIGHUP == sig) {
		rc = get_pid_from_file(PID_FILE_LOC, &killpid);
		if (rc) {
			fprintf(stderr, "Failed to read pid from file %s", PID_FILE_LOC);
			killpid = KILL_PID_NONE;
		}
	}
	else
	{
		interrupted = sig;
	}
}


// Kills the current domU process by corrupting its state upon a
// syscall. May need further work.
//
// Reference linux kernel:
// arch/x86/entry/entry_64.S
// arch/arm64/kernel/entry.S

static void
linux_kill_curr_proc (vmi_instance_t vmi, vmi_event_t * event)
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
	if (VMI_FAILURE == status)
	{
		fprintf(stderr, "Failed to write X0 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X1, event->vcpu_id);
	if (VMI_FAILURE == status)
	{
		fprintf(stderr, "Failed to write X1 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X2, event->vcpu_id);
	if (VMI_FAILURE == status)
	{
		fprintf(stderr, "Failed to write X2 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X3, event->vcpu_id);
	if (VMI_FAILURE == status)
	{
		fprintf(stderr, "Failed to write X3 register\n");
		goto exit;
	}
	status = vmi_set_vcpureg(vmi, 0, X4, event->vcpu_id);
	if (VMI_FAILURE == status)
	{
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








int inst_syscall(nif_xen_monitor *xa, const char * in_path){

	FILE *input_file = NULL;
	char *name = NULL;
	char one_line[1024];
	char *nl = NULL;
	addr_t sys_va;
	uint32_t backup_smc1;
	uint32_t backup_smc2;


	input_file = fopen(in_path, "r+");


	if (NULL == input_file) {
		printf("\nCant open system map file\n");
		return -1;
	}

	while( fgets( one_line, 1000, input_file) != NULL){

		if(NULL == (name = strstr(one_line, " T "))){ //find the global text section symbols
			//printf("\nDidn't find any text symbol");
			continue;
		}

		//Doing this coz case insensitive function was behaving weirdly
		if(NULL==strstr(one_line, " sys_")){
			if(NULL==strstr(one_line, " SyS_")){

				if(NULL==strstr(one_line, " Sys_")){ //possible sys_call

					//printf("\nFound text_sec but didn't find any sys_call symbol in %s", one_line);
					continue;
				}
			}//second if

		}//first if

		*name = '\0';
		sys_va = (addr_t) strtoul(one_line, NULL, 16);

		name = name +3;
		if(NULL != (nl =strchr(name, '\n')))
			*nl='\0';



		if ( (VMI_FAILURE == vmi_read_32_va(xa->vmi, sys_va, 0, &backup_smc1)) ||

			 (VMI_FAILURE == vmi_read_32_va(xa->vmi, sys_va+4, 0, &backup_smc2)) ) {

			printf("\nUnable to read %s() instructions from va:%" PRIx64 " for smc backup", name, sys_va);
			continue;
		}


		//printf("\nAddress Extracted: %s Address Converted: %" PRIx64 " Backup Inst: %" PRIx32 "\n", one_line, sys_va, backup_smc1);


		if(NULL == setup_spg_bp(xa, sys_va, name, backup_smc1, backup_smc2)){
			printf("\nFailed to add pg/bp for %s at %" PRIx64 "", name, sys_va);
			return -1;
		}
		act_calls++;

		if(act_calls == MAX_CALLS-1)//max syscalls that we want to monitor
			break;

	}//while ends

	fclose(input_file);

	return 0;

}

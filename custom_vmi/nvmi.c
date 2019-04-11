/*
Description: Monitor Linux syscalls outside of OS via Virtual Machine Introspection (VMI)
Company: Numen Inc.
Developers: Ali Islam
Version: 1.0
Input: <VM Name> <Path to sys_map file>
Output: Syscall_name, PID, Processname, CR3
*/


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include "nvmi.h"
#include <libvmi/libvmi.h>
#include <libvmi/events.h>



static uint8_t trap = 0xCC;
static vmi_event_t ss_event[MAX_VCPUS];
static int act_calls = 0;
sys_node * sys_calls[MAX_CALLS];


/* Signal handler */
static struct sigaction act;
static int interrupted = 0;
static void close_handler(int sig){
    interrupted = sig;
}




static int get_proc_name_lnx(vmi_instance_t vmi, vmi_pid_t pid, char *proc_arr){

	addr_t plist_head = 0, cur_pnode = 0, next_pnode = 0;
	    addr_t current_process = 0;
	    vmi_pid_t curr_pid = 0;
	    addr_t tasks_offset = 0, pid_offset = 0, name_offset = 0;
	    status_t status;
	    char *procname;

	    if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &tasks_offset) )
			return -1;
		if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_offset) )
			return -1;
		if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_offset) )
			return -1;

		if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", &plist_head) ){
			printf("\nUnable to get the start of plist");
			return -1;
		}

		plist_head += tasks_offset;
		cur_pnode = plist_head;

	    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_pnode, 0, &next_pnode)) {
	            printf("Failed to read next node from %"PRIx64"\n", cur_pnode);
	            return -1;
	    }


	        while (1) {

	            current_process = cur_pnode - tasks_offset; //Since its in mem so we need to go backwards
	            vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&curr_pid);
	            if(curr_pid == pid){

	            	procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
	            	if (!procname)
	            	  printf("Pid matched but failed to find procname\n");
	            	else {
	            	  //printf("\nProcess name found %s\n", procname);

	            	  strncpy(proc_arr, procname, 510);

	            	  /* Need to free the memory assigned by the vmi_read_str_va() api*/

	            	  free(procname);
	            	}



	            	break;
	            }


				cur_pnode = next_pnode;
				status = vmi_read_addr_va(vmi, cur_pnode, 0, &next_pnode);
				if (status == VMI_FAILURE) {
					printf("Failed to read next node from %"PRIx64"\n", cur_pnode);
					return -1;
				}

				if (cur_pnode == plist_head) {

					printf("End of list: Process name not found\n");
				   break;
				}

	        };//while ends


}



event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {

	addr_t temp = event->ss_event.gla;

	    vmi_write_8_va(vmi, temp-1, 0, &trap);


	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);
}

static int  setup_ss_events (vmi_instance_t vmi)
{

	int vcpus = vmi_get_num_vcpus(vmi);
    printf("\nDomain vcpus=%d\n", vcpus);

	if (0 == vcpus) {
		printf("Failed to find the total VCPUs\n");
		return -1;
	}

	if (vcpus > MAX_VCPUS) {
		printf("Guest VCPUS are greater than what we can support\n");
		return -1;
	}

	for (int i = 0; i < vcpus; i++) {

		SETUP_SINGLESTEP_EVENT(&ss_event[i], 1u << i, singlestep_cb,0);


		if (VMI_SUCCESS != vmi_register_event(vmi, &ss_event[i])) {
			printf("Failed to register SS event on VCPU failed %d\n", i);
			return -1;
		}
	}

	return 1;
}



int get_sindex(addr_t sys_addr){

	int i=0;


	for (i=0; i<act_calls; i++) {

	    	if(sys_calls[i]->sys_addr == sys_addr)

	    		return i;



	}

	return -1;
}


event_response_t hook_cb(vmi_instance_t vmi, vmi_event_t *event) {

	//TODO: Do a check to see if its our breakpoint or some legit vm user.

    reg_t cr3, rax,rsi,rcx,rdx,rdi,eip;

    vmi_pid_t pid = -1;
    char proc_arr[512];
    char * procname = proc_arr;
    int s_index = 0;

    if(-1 == (s_index=get_sindex(event->interrupt_event.gla))){
    	printf("\nhook_cb: Unable to find record for address %" PRIx16 "", event->interrupt_event.gla);
    	exit;
    }


    vmi_write_8_va(vmi, event->interrupt_event.gla, 0, &sys_calls[s_index]->backup_byte);


    vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id);
    vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);

    //Get PID
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    vmi_dtb_to_pid(vmi, cr3, &pid);
    if(-1 == pid)
    	printf("\nFaild to get the pid");

    //Get process name
    get_proc_name_lnx(vmi, pid, procname);

    printf("NumenVmi: %s() was called by Process: %s Pid=%d, Cr3=%" PRIx16 "\n",
    	    sys_calls[s_index]->name , procname,pid, (unsigned int)cr3);


    event->interrupt_event.reinject = 0; 


    return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);
}

int inst_syscall(vmi_instance_t vmi, const char * in_path){

	FILE *input_file = NULL;
	char *tmp = NULL;
	char one_line[1024];
	char *nl = NULL;


	input_file = fopen(in_path, "r+");


	if (NULL == input_file) {
		printf("\nCant open system map file\n");
		return 0;
	}

	 while( fgets( one_line, 1000, input_file) != NULL){

		 if(NULL == (tmp = strstr(one_line, " T "))){ //find the global text section symbols
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

		 *tmp = '\0'; //extract

		 sys_calls[act_calls]= (sys_node*)malloc(sizeof(sys_node));


		 sys_calls[act_calls]->sys_addr = (addr_t) strtoul(one_line, NULL, 16);//copy address

		 if(NULL != (nl =strchr(tmp+3, '\n')))
			 *nl='\0';

		 strncpy(sys_calls[act_calls]->name, tmp+3, 128); //copy syscall_name
		 //backup and insert trap

			vmi_read_8_va(vmi, sys_calls[act_calls]->sys_addr, 0, &sys_calls[act_calls]->backup_byte);

		 //printf("\nAddress Extracted: %s Address Converted: 0x%lx Backup Byte: 0x%lx\n", one_line, strtoul(one_line, NULL, 16), sys_calls[act_calls]->backup_byte);

			vmi_write_8_va(vmi, sys_calls[act_calls]->sys_addr, 0, &trap);

		 //printf("\nHook added at 0x%lx", sys_calls[act_calls]->sys_addr);

		 //list = g_slist_append(list, sys_calls[act_calls]);
		 act_calls++;

		  if(act_calls == MAX_CALLS-1)//max syscalls that we want to monitor
			  break;

	 }//while ends

	fclose(input_file);


}


int main(int argc, char **argv) {


	//vmi_event_t trap_event, singlestep_event;
	vmi_event_t trap_event;

    if (argc != 3) {
        printf("Usage: %s <domain name> <path to system_map>\n");
        return 1;
    }

    status_t status;
    const char *name = argv[1];
    const char *in_path = argv[2];
    int i = 0;

    /* Handle ctrl+c properly */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

	vmi_instance_t vmi;
	// Initialize the libvmi library.
    if (VMI_FAILURE ==
            vmi_init_complete(&vmi, (void *)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS, NULL,
                              VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        printf("Failed to init LibVMI library.\n");
        return 1;
    }

    printf("\n\t\tNumen Introspection Framework v1.0\n\n");

	vmi_pause_vm(vmi);


	inst_syscall(vmi, in_path);


	if(-1 == setup_ss_events(vmi))
			goto graceful_exit;


	SETUP_INTERRUPT_EVENT(&trap_event, 0, hook_cb);
	if (VMI_SUCCESS != vmi_register_event(vmi, &trap_event)){
		printf("\nUnable to register Interrupt event");
		goto graceful_exit;
	}


	vmi_resume_vm(vmi);
    while(!interrupted){
	    status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Some issue in the event_listen loop. Aborting!\n");
            interrupted = -1;
        }
	}


graceful_exit:

    for (i=0; i<act_calls; i++) {

    	vmi_write_8_va(vmi, sys_calls[i]->sys_addr, 0, &sys_calls[i]->backup_byte);//replace orig instruction

    	free(sys_calls[i]);//free the dynamic memory

    }


    vmi_destroy(vmi);
    return 0;
}

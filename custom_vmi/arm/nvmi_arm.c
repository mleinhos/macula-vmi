/*
Description: Monitor Linux syscalls on ARM. It creates shadow pages in memory & switches between different views to achieve single stepping functionality on Xen-Arm.

Company: Numen Inc.

Developer: Ali Islam

Input: <VM Name> <Path to sys_map file>

Output: Syscall_name, PID, Processname
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

static int act_calls = 0;
uint16_t sm1_view;
static uint32_t trap_arm = 0xD4000003;

#define KILL_PID_NONE ((vmi_pid_t)-1)
static vmi_pid_t killpid = KILL_PID_NONE;


/* Signal handler */
static struct sigaction act;
static int interrupted = 0;
static void close_handler(int sig){
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



static void
free_pg_hks_lst (gpointer data) {

	nif_hook_node *hook_node = data;

	vmi_write_32_pa(hook_node->parent->xa->vmi,
			(hook_node->parent->shadow_frame << PG_OFFSET_BITS) + hook_node->offset,
			&hook_node->backup_smc1);

	vmi_write_32_pa(hook_node->parent->xa->vmi,
				(hook_node->parent->frame << PG_OFFSET_BITS) + hook_node->offset +4,
				&hook_node->backup_smc2);

	g_free(hook_node);
}


static void
free_nif_page_node (gpointer data) {


	nif_page_node *pnode = data;

	g_hash_table_destroy(pnode->offset_bp_mappings);

	// Stop monitoring
	vmi_set_mem_event(pnode->xa->vmi,
			pnode->shadow_frame,
			VMI_MEMACCESS_N,
			sm1_view);

	xc_altp2m_change_gfn(pnode->xa->xci, pnode->xa->domain_id,sm1_view,pnode->frame,~(0UL));


	xc_altp2m_change_gfn(pnode->xa->xci, pnode->xa->domain_id,sm1_view,pnode->shadow_frame,~(0UL));


	xc_domain_decrease_reservation_exact(pnode->xa->xci,
			pnode->xa->domain_id,
			1, 0,
			(xen_pfn_t*)&pnode->shadow_frame);

	g_free(pnode);
}



static nif_hook_node *
setup_spg_bp (nif_xen_monitor *xa, addr_t va, const char *name, uint32_t backup_smc1, uint32_t backup_smc2) {

	size_t ret;
	status_t status;
	nif_page_node  *pgnode_new  = NULL;
	nif_hook_node *bp_new = NULL;
	addr_t pa, frame, shadow, shadow_offset;
	uint8_t buff[DOM_PAGE_SIZE] = {0};
	addr_t dtb = 0;


	if(VMI_FAILURE == vmi_pid_to_dtb(xa->vmi, 0, &dtb)){
		printf("Shadow: Couldn't get dtb\n");
		goto done;
	}


	if (VMI_SUCCESS != vmi_pagetable_lookup(xa->vmi,dtb,va,&pa)){

		printf("Shadow: Couldn't get pagetable information\n");
		goto done;
	}


	frame = pa >> PG_OFFSET_BITS;

	shadow = (addr_t) GPOINTER_TO_SIZE(g_hash_table_lookup(xa->pframe_sframe_mappings,
				GSIZE_TO_POINTER(frame)));
	shadow_offset = pa % DOM_PAGE_SIZE;


	//Allocate frame if not already there
	if (0 == shadow) {

		shadow = ++(xa->max_gpfn);



		if( xc_domain_populate_physmap_exact(xa->xci, xa->domain_id, 1, 0,0, (xen_pfn_t*)&shadow) < 0) {

			printf("Failed to allocate frame at %" PRIx64 "\n", shadow);
			goto done;
		}


		g_hash_table_insert(xa->pframe_sframe_mappings, //create new translation
				GSIZE_TO_POINTER(frame),
				GSIZE_TO_POINTER(shadow));


		// Update p2m mapping
		if (0 != xc_altp2m_change_gfn(xa->xci, xa->domain_id, sm1_view, frame ,shadow)){
			printf("Shadow: Unable to change mapping for sm1_view\n");
			goto done;
		}

	}

	pgnode_new = g_hash_table_lookup(xa->shadow_pnode_mappings, GSIZE_TO_POINTER(shadow));

	if (NULL == pgnode_new) {

		status = vmi_read_pa(xa->vmi,
				frame << PG_OFFSET_BITS,
				DOM_PAGE_SIZE,
				buff,
				&ret);
		if (DOM_PAGE_SIZE!= ret || status == VMI_FAILURE) {
			printf("Shadow: Failed to read syscall page\n");
			goto done;
		}

		status = vmi_write_pa(xa->vmi,
				shadow << PG_OFFSET_BITS,
				DOM_PAGE_SIZE,
				buff,
				&ret);
		if (DOM_PAGE_SIZE!= ret || status == VMI_FAILURE) {
			printf("Shadow: Failed to write to shadow page\n");
			goto done;
		}


		// Update the hks list
		pgnode_new              = g_new0(nif_page_node, 1);
		pgnode_new->shadow_frame = shadow;
		pgnode_new->frame       = frame;
		pgnode_new->xa        = xa;
		pgnode_new->offset_bp_mappings    = g_hash_table_new_full(NULL, NULL,NULL,free_pg_hks_lst);

		g_hash_table_insert(xa->shadow_pnode_mappings,
				GSIZE_TO_POINTER(shadow),
				pgnode_new);

	} else {
		//Check for existing hooks
		bp_new = g_hash_table_lookup(pgnode_new->offset_bp_mappings,
				GSIZE_TO_POINTER(shadow_offset));
		if (NULL != bp_new) {
			goto done;
		}
	}

	bp_new             = g_new0(nif_hook_node, 1);
	bp_new->offset     = shadow_offset;
	bp_new->backup_smc1 = backup_smc1;
	bp_new->backup_smc2 = backup_smc2;
	strncpy(bp_new->name, name, MAX_SNAME_LEN);
	bp_new->parent     = pgnode_new;

	status = vmi_write_32_pa(xa->vmi,
			(shadow << PG_OFFSET_BITS) + shadow_offset,
			&trap_arm);

	status = vmi_write_32_pa(xa->vmi,
				(frame << PG_OFFSET_BITS) + shadow_offset +4, //write the second smc to orig view
				&trap_arm);


	if (VMI_SUCCESS != status) {
		printf("Failed to add required SMCs for single stepping\n");
		goto done;
	}

	g_hash_table_insert(pgnode_new->offset_bp_mappings,
			GSIZE_TO_POINTER(shadow_offset),
			bp_new);

	//printf("\nInside: New bp node inserted with offset %" PRIx64 "", shadow_offset);

done:

	return bp_new;
}


static int get_proc_name_lnx_2(vmi_instance_t vmi, vmi_pid_t pid, char *proc_arr){

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

		current_process = cur_pnode - tasks_offset;
		vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&curr_pid);
		if(curr_pid == pid){

			procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
			if (!procname)
				printf("Pid matched but failed to find procname\n");
			else {
				//printf("\nProcess name found %s\n", procname);

				strncpy(proc_arr, procname, MAX_SNAME_LEN);

				// checked the vmi header: its our responsibility to free

				free(procname);
				return 1;
			}


			printf("\nPid matched but unable to find process name");
			return -1;
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

	return -1;

}



static int get_proc_name_lnx_1(vmi_instance_t vmi, unsigned long vcpu_id, vmi_pid_t *curr_pid, char*procname){

	addr_t curr_task = 0;
	addr_t name_offset =0;
	addr_t pid_offset =0;
	char *proc_name = NULL;


	if( VMI_FAILURE == vmi_get_vcpureg(vmi, &curr_task, SP_EL0, vcpu_id)){

		printf("\nFaild to get the current task from sp_el0");
				return -1;
	}

	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_offset) ){
		printf("\nFaild to get the name_offset");
		return -1;
	}

	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_offset) ){
		printf("\nFaild to get the pid_offset");
		return -1;
	}


	if ( VMI_FAILURE == vmi_read_32_va(vmi, curr_task + pid_offset, 0, (uint32_t*)curr_pid)){

		printf("\nFaild to Failed to read PID from pid_offset");
				return -1;
	}


	proc_name = vmi_read_str_va(vmi, curr_task + name_offset, 0);
	if (!proc_name) {
		printf("\n No process_name found at the name offset");
		return -1;
	}

	strncpy(procname, proc_name, MAX_SNAME_LEN-1);

	//printf("\nFast try: p_name: %s, pid: %d\n", procname, *curr_pid);

	free(proc_name);

	return 1;




}

event_response_t hook_cb(vmi_instance_t vmi, vmi_event_t *event) {


	reg_t ttbr0, ttbr1;

	vmi_pid_t pid = -1;
	char proc_arr[MAX_SNAME_LEN];
	char * procname = proc_arr;
	int s_index = 0;
	nif_page_node * pgnode_temp = NULL;
	nif_hook_node * h_node_temp = NULL;
	addr_t shadow = 0;


	if (event->slat_id == 0){ //sw single step
			event-> slat_id = sm1_view;
			return (VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
	}




	nif_xen_monitor *xa = event->data;

	if(0 == (shadow = (addr_t) GPOINTER_TO_SIZE(g_hash_table_lookup(xa->pframe_sframe_mappings ,
						GSIZE_TO_POINTER(event->privcall_event.gfn))))) {

        //No need to reinject since smc is not available to guest
		return VMI_EVENT_RESPONSE_NONE;

	}


	if(NULL == (pgnode_temp = g_hash_table_lookup(xa->shadow_pnode_mappings,
					GSIZE_TO_POINTER(shadow)))) {

		printf("\n Can't find pg_node for shadow: %" PRIx32"", shadow);

		return VMI_EVENT_RESPONSE_NONE;

	}

	if(NULL == (h_node_temp = g_hash_table_lookup(pgnode_temp->offset_bp_mappings,
					GSIZE_TO_POINTER(event->privcall_event.offset)))) {

		printf("\nhook_cb Warning: No BP record found for this offset %" PRIx64 " on page %" PRIx16 "",
				event->privcall_event.offset, event->privcall_event.gfn);

		return VMI_EVENT_RESPONSE_NONE;

	}

	vmi_get_vcpureg(vmi, &ttbr0, TTBR0, event->vcpu_id);
	vmi_get_vcpureg(vmi, &ttbr1, TTBR1, event->vcpu_id);

	if (1 == get_proc_name_lnx_1(vmi, event->vcpu_id, &pid, procname)){

		printf("NumenVmi Log: sys_call=%s,	process_name=%s,	pid=%d, TTBR0=%" PRIx32 ",	TTBR1=%" PRIx32 "\n",
				h_node_temp->name , procname,pid, (unsigned int)ttbr0, (unsigned int)ttbr1);
	}

	if (pid == killpid) {
		printf ("Attempting to kill process PID=%d\n", pid);
		printf ("\tname: %s\n", procname);
		linux_kill_curr_proc(vmi, event);
	}

	if (event->slat_id == sm1_view)
				 event-> slat_id = 0;


	return (VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);

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

static event_response_t
cr3_cb(vmi_instance_t vmi, vmi_event_t *event) {


	event->x86_regs->cr3 = event->reg_event.value;

	//Flush process_related caches for clean start and consistency

	vmi_symcache_flush(vmi);
	vmi_pidcache_flush(vmi);
	vmi_v2pcache_flush(vmi, event->reg_event.previous);
	vmi_rvacache_flush(vmi);


	return VMI_EVENT_RESPONSE_NONE;
}


static event_response_t
mem_intchk_cb (vmi_instance_t vmi, vmi_event_t *event) {



	printf("\nIntegrity check served\n");

	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
		| VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}


static void clean_xen_monitor(nif_xen_monitor *xa)
{

	if (xa->xcx)
		if (0 != libxl_ctx_free(xa->xcx))
			printf("Failed to close xl handle\n");


	if (xa->xci)
		if(0!= xc_interface_close(xa->xci))
			printf("Failed to close connection to xen interface\n");

	xc_domain_setmaxmem(xa->xci, xa->domain_id, xa->orig_mem_size);



}

static void destroy_views(nif_xen_monitor *xa, uint32_t domain_id) {

	if(0!= xc_altp2m_switch_to_view(xa->xci, domain_id, 0))
		printf("Failed to switch to exe view in func destroy_view\n");

	if (sm1_view )
		xc_altp2m_destroy_view(xa->xci, domain_id, sm1_view);

	if(0!= xc_altp2m_set_domain_state(xa->xci, domain_id, 0))
		printf("Failed to disable alternate view for domain_id: %u\n",domain_id);


}



static int inst_xen_monitor(nif_xen_monitor *xa, const char *name)
{
	if(0 == (xa->xci = xc_interface_open(NULL, NULL, 0))){
		printf("Failed to open xen interface\n");
		return -1; // nothing to clean
	}



	if (libxl_ctx_alloc(&xa->xcx, LIBXL_VERSION, 0, NULL)){
		printf("Unable to create xl context\n");
		goto clean;
	}


	if ( libxl_name_to_domid(xa->xcx, name, &xa->domain_id)){
		printf("Unable to get domain id for %s\n", name);
		goto clean;
	}

	if(0 == (xa->orig_mem_size = vmi_get_memsize(xa->vmi))) {
		printf("Failed to get domain memory size\n");
		goto clean;
	}



	if (xc_domain_maximum_gpfn(xa->xci, xa->domain_id, &xa->max_gpfn) < 0){
		printf("Failed to get max gpfn for the domain\n");
		goto clean;
	}

	//printf("\nMax gfn:%" PRIx64 "",xa->max_gpfn);



	return 1;

clean:

	clean_xen_monitor(xa);

	return -1;
}




int main(int argc, char **argv) {

	if (argc != 3) {
		printf("Usage: %s <domain name> <path to system_map>\n", argv[0]);
		return 1;
	}

	status_t status;
	const char *name = argv[1];
	const char *in_path = argv[2];
	nif_xen_monitor xa;
	vmi_event_t trap_event, mem_event, cr3_event;


	/* Handle ctrl+c properly */
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);




	// Initialize the libvmi library.
	if (VMI_FAILURE ==
			vmi_init_complete(&xa.vmi, (void *)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS,NULL,
				VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
		printf("Failed to init LibVMI library.\n");
		goto graceful_exit;
	}

	if(-1 == inst_xen_monitor(&xa, name))
		return -1;


	printf("\n\t\t\tNumen Introspection Framework v3.0\n\n");


	xa.pframe_sframe_mappings = g_hash_table_new(NULL, NULL);
	xa.shadow_pnode_mappings = g_hash_table_new_full(NULL, NULL,NULL,free_nif_page_node);



	vmi_pause_vm(xa.vmi);

	if(0!= xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 1)){
		printf("Failed to enable altp2m for domain_id: %u\n", xa.domain_id);
		goto graceful_exit;
	}



	if(0!= xc_altp2m_create_view(xa.xci, xa.domain_id, 0, &sm1_view)){
		printf("Failed to create smc1 view\n");
		goto graceful_exit;
	}


	if(0!= xc_altp2m_switch_to_view(xa.xci, xa.domain_id, sm1_view)){
		printf("Failed to switch to smc1 view id:%u\n", sm1_view);
		goto graceful_exit;
	}

	printf("\nAltp2m: sm1_view created and activated");


	if (-1 == inst_syscall(&xa, in_path))
		goto graceful_exit;



	SETUP_PRIVCALL_EVENT(&trap_event, hook_cb);
	trap_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event(xa.vmi, &trap_event)){
		printf("\nUnable to register privcall event");
		goto graceful_exit;
	}



	printf("\nMemory pages created and configured for ARM single stepping. Monitoring now..\n\n");

	vmi_resume_vm(xa.vmi);
	while(!interrupted){
		status = vmi_events_listen(xa.vmi,500);
		if (status != VMI_SUCCESS) {
			printf("Some issue in the event_listen loop. Aborting!\n\n");
			interrupted = -1;
		}
	}


graceful_exit:

	vmi_pause_vm(xa.vmi);

	fflush(stdout);
	g_hash_table_destroy(xa.shadow_pnode_mappings);
	g_hash_table_destroy(xa.pframe_sframe_mappings);

	destroy_views(&xa, xa.domain_id);

	clean_xen_monitor(&xa);

	vmi_resume_vm(xa.vmi);

	vmi_destroy(xa.vmi);
	return 0;
}

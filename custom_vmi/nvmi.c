/*
Description: Monitor Linux syscalls using altp2m. It creates shadow pages in memory &
switches between different views to provide stealthiness and speed.

Company: Numen Inc.

Developer: Ali Islam

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
#include <czmq.h>
#include <pthread.h>

//#define ZMQ_HOST "localhost"
//#define ZMQ_EVENT_CHANNEL "tcp://localhost:5555"
#define ZMQ_EVENT_CHANNEL "tcp://*:5555"
#define ZMQ_REQUEST_CHANNEL "tcp://localhost:5556"


static vmi_event_t ss_event[MAX_VCPUS];
static int act_calls = 0;
uint16_t exe_view;
static uint8_t trap_cc = 0xCC;

static void* zmq_context = NULL;
static void* zmq_event_socket  = NULL;
static void* zmq_request_socket  = NULL;

static pthread_t pth_request_servicer;

/* Signal handler */
static struct sigaction act;
static int interrupted = 0;
static void close_handler(int sig)
{
	interrupted = sig;
}



static void
free_pg_hks_lst (gpointer data)
{

	nif_hook_node* hook_node = data;

	vmi_write_8_pa(hook_node->parent->xa->vmi,
	               (hook_node->parent->shadow_frame << PG_OFFSET_BITS) + hook_node->offset,
	               &hook_node->backup_byte);

	g_free(hook_node);
}


static void
free_nif_page_node (gpointer data)
{


	nif_page_node* pnode = data;

	g_hash_table_destroy(pnode->offset_bp_mappings);

	// Stop monitoring
	vmi_set_mem_event(pnode->xa->vmi,
	                  pnode->shadow_frame,
	                  VMI_MEMACCESS_N,
	                  exe_view);

	xc_altp2m_change_gfn(pnode->xa->xci, pnode->xa->domain_id,exe_view,pnode->frame,~(0UL));


	xc_altp2m_change_gfn(pnode->xa->xci, pnode->xa->domain_id,exe_view,pnode->shadow_frame,~(0UL));


	xc_domain_decrease_reservation_exact(pnode->xa->xci,
	                                     pnode->xa->domain_id,
	                                     1, 0,
	                                     (xen_pfn_t*)&pnode->shadow_frame);

	g_free(pnode);
}



static nif_hook_node*
setup_spg_bp (nif_xen_monitor* xa, addr_t va,const char* name,uint8_t backup_byte)
{

	size_t ret;
	status_t status;
	nif_page_node*  pgnode_new  = NULL;
	nif_hook_node* bp_new = NULL;
	addr_t pa, frame, shadow, shadow_offset;
	uint8_t buff[DOM_PAGE_SIZE] = {0};
	addr_t dtb = 0;



	if (VMI_FAILURE == vmi_pid_to_dtb(xa->vmi, 0, &dtb)) {
		printf("Shadow: Couldn't get cr3\n");
		goto done;
	}


	if (VMI_SUCCESS != vmi_pagetable_lookup(xa->vmi,dtb,va,&pa)) {

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



		if ( xc_domain_populate_physmap_exact(xa->xci, xa->domain_id, 1, 0,0, (xen_pfn_t*)&shadow) < 0) {

			printf("Failed to allocate frame at %" PRIx64 "\n", shadow);
			goto done;
		}


		g_hash_table_insert(xa->pframe_sframe_mappings, //create new translation
		                    GSIZE_TO_POINTER(frame),
		                    GSIZE_TO_POINTER(shadow));


		// Update p2m mapping
		if (0 != xc_altp2m_change_gfn(xa->xci, xa->domain_id, exe_view, frame,shadow)) {
			printf("Shadow: Unable to change mapping for exe_view\n");
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

		//Activate monitoring for this page.
		status = vmi_set_mem_event(xa->vmi,
		                           shadow,
		                           VMI_MEMACCESS_RW,
		                           exe_view);
		if (VMI_SUCCESS != status) {
			printf("Shadow: Couldn't set frame permissions for %" PRIx64 "\n", shadow);
			goto done;
		}
		//printf("\nInside: Monitoring on shadow page activated");

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
	bp_new->backup_byte = backup_byte;
	strncpy(bp_new->name, name, MAX_SNAME_LEN);
	bp_new->parent     = pgnode_new;

	status = vmi_write_8_pa(xa->vmi,
	                        (shadow << PG_OFFSET_BITS) + shadow_offset,
	                        &trap_cc);

	if (VMI_SUCCESS != status) {
		printf("Failed to write interrupt to shadow page\n");
		goto done;
	}

	g_hash_table_insert(pgnode_new->offset_bp_mappings,
	                    GSIZE_TO_POINTER(shadow_offset),
	                    bp_new);

	//printf("\nInside: New bp node inserted with offset %" PRIx64 "", shadow_offset);

done:

	return bp_new;
}


static int get_proc_name_lnx_2(vmi_instance_t vmi, vmi_pid_t pid, char* proc_arr)
{

	addr_t plist_head = 0, cur_pnode = 0, next_pnode = 0;
	addr_t current_process = 0;
	vmi_pid_t curr_pid = 0;
	addr_t tasks_offset = 0, pid_offset = 0, name_offset = 0;
	status_t status;
	char* procname;

	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &tasks_offset) )
		return -1;
	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_offset) )
		return -1;
	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_offset) )
		return -1;

	if ( VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", &plist_head) ) {
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
		if (curr_pid == pid) {

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



event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t* event)
{


	event-> slat_id = exe_view;

	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP|
	        VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

static int  setup_ss_events (vmi_instance_t vmi)
{

	int vcpus = vmi_get_num_vcpus(vmi);
	printf("\nDomain vcpus=%d", vcpus);

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


static addr_t
get_curr_task(vmi_instance_t vmi, addr_t gs_base)
{
	status_t status;
	addr_t current_task = 0;
	static addr_t current_task_offset = 0;


	vmi_translate_ksym2v(vmi, "per_cpu__current_task", &current_task_offset);


	if (!current_task_offset) {
		vmi_translate_ksym2v(vmi, "current_task", &current_task_offset);
	}

	if (!current_task_offset) {
		printf("\nFast try: Error could get the current_task offset.\n");
		goto done;
	}

	status = vmi_read_addr_va(vmi,gs_base+ current_task_offset,
	                          0,
	                          &current_task);
	if (VMI_SUCCESS != status) {
		current_task = 0;
		printf("\nFast try: Fail to read anything at base+curr_task_offset");
		goto done;
	}

done:
	return current_task;
}

static int get_proc_name_lnx_1(vmi_instance_t vmi, unsigned long vcpu_id, vmi_pid_t* curr_pid, char* procname)
{

	reg_t base_reg, gs_base;
	addr_t curr_task = 0;
	addr_t name_offset =0;
	addr_t pid_offset =0;
	char* proc_name = NULL;


	if (8 == vmi_get_address_width(vmi))
		base_reg = GS_BASE; // for 64-bit
	else
		base_reg = FS_BASE; //for 32-bit

	vmi_get_vcpureg(vmi, &gs_base, base_reg, vcpu_id);

	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_offset) ) {
		printf("\nFaild to get the name_offset in hook_cb");
		return -1;
	}
	if ( VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_offset) ) {
		printf("\nFaild to get the pid_offset in hook_cb");
		return -1;
	}


	if (0== (curr_task= get_curr_task(vmi, gs_base))) {
		printf("\nAlternative: Unable to find current_task struct");
		return -1;
	}

	vmi_read_32_va(vmi, curr_task + pid_offset, 0, (uint32_t*)curr_pid);


	proc_name = vmi_read_str_va(vmi, curr_task + name_offset, 0);
	if (!proc_name) {
		printf("\n No process_name found using fast try");
		return -1;
	}

	strncpy(procname, proc_name, MAX_SNAME_LEN-1);

	//printf("\nFast try: p_name: %s, pid: %d\n", procname, *curr_pid);

	free(proc_name);

	return 1;




}

event_response_t hook_cb(vmi_instance_t vmi, vmi_event_t* event)
{


	reg_t cr3, rax,rsi,rcx,rdx,rdi,eip;

	vmi_pid_t pid = -1;
	char proc_arr[MAX_SNAME_LEN];
	char* procname = proc_arr;
	int s_index = 0;
	nif_page_node* pgnode_temp = NULL;
	nif_hook_node* h_node_temp = NULL;
	addr_t shadow = 0;
	bool data_found = false;




	nif_xen_monitor* xa = event->data;

	if (0 == (shadow = (addr_t) GPOINTER_TO_SIZE(g_hash_table_lookup(xa->pframe_sframe_mappings,
	                   GSIZE_TO_POINTER(event->interrupt_event.gfn))))) {

		event->interrupt_event.reinject = 1;
		return VMI_EVENT_RESPONSE_NONE;

	}


	if (NULL == (pgnode_temp = g_hash_table_lookup(xa->shadow_pnode_mappings,
	                           GSIZE_TO_POINTER(shadow)))) {

		printf("\n Can't find pg_node for shadow: %" PRIx32"", shadow);

		event->interrupt_event.reinject = 1;
		return VMI_EVENT_RESPONSE_NONE;

	}

	if (NULL == (h_node_temp = g_hash_table_lookup(pgnode_temp->offset_bp_mappings,
	                           GSIZE_TO_POINTER(event->interrupt_event.offset)))) {

		printf("\nhook_cb Warning: No BP record found for this offset %" PRIx64 " on page %" PRIx16 "",
		       event->interrupt_event.offset, event->interrupt_event.gfn);
		event->interrupt_event.reinject = 1;
		return VMI_EVENT_RESPONSE_NONE;

	}


	//vmi_get_vcpureg(vmi, &rdi, RDI, event->vcpu_id);
	//vmi_get_vcpureg(vmi, &rsi, RSI, event->vcpu_id);
	//vmi_get_vcpureg(vmi, &rax, RAX, event->vcpu_id);



	if (1 == get_proc_name_lnx_1(vmi, event->vcpu_id, &pid, procname))
		data_found =true;


	if (!data_found) {

		vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);

		if (-1 == vmi_dtb_to_pid(vmi, cr3, &pid)) {

			printf("\n2nd procname try: Faild to get the pid");
			goto done;
		}



		if (-1 == get_proc_name_lnx_2(vmi, pid, procname)) {
			printf("\n 2nd procname try: Unable to find process name for pid:%d", pid);
			goto done;
		} else
			data_found = true;
	}


	if (data_found) {
		char data[128];
		size_t len = 0;
		int rc = 0;
		printf("NumenVmi Log: sys_call=%s, process_name=%s, pid=%d, cr3=%" PRIx16 "\n",
		       h_node_temp->name, procname,pid, (unsigned int)cr3);

		len = snprintf (data, sizeof(data), "%s proc=%s pid=%d cr3=%llx\n",
		                h_node_temp->name, procname,pid, (unsigned int)cr3);

		rc = zmq_send (zmq_event_socket, data, len+1, 0);
		if (rc < 0) {
			fprintf(stderr, "zmq_send() failed: %d\n", rc);
		}
	}
done:

	event->interrupt_event.reinject = 0;

	event-> slat_id = 0;

	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP|
	        VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

int inst_syscall(nif_xen_monitor* xa, const char* in_path)
{

	FILE* input_file = NULL;
	char* name = NULL;
	char one_line[1024];
	char* nl = NULL;
	addr_t sys_va;
	uint8_t backup_byte;


	input_file = fopen(in_path, "r+");


	if (NULL == input_file) {
		printf("\nCant open system map file\n");
		return -1;
	}

	while ( fgets( one_line, 1000, input_file) != NULL) {

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

		name = name +3;
		if (NULL != (nl =strchr(name, '\n')))
			*nl='\0';

		printf ("Instrumenting symbol %s\n", name);

		// skip some symbols
		if (!strcmp(name, "sys_ni_syscall")           ||
		    !strcmp(name, "sys_call_table")           ||
		    !strncmp(name, "sys_dmi", 7)              ||
		    !strcmp(name,  "sys_tz")                  || /* used by gettimeofday */
		    !strcmp(name,  "sys_tracepoint_refcount") ||
		    !strcmp(name,  "sys_table")               ||
		    !strcmp(name,  "sys_perf_refcount_enter") ||
		    !strcmp(name,  "sys_perf_refcount_exit")   ) {
			printf ("Skipping symbol %s\n", name);
			continue;
		}

//		if (strncmp(name, "__x64_sys_", 10)) {
//			printf ("Skipping symbol %s\n", name);
//			continue;
//		}

		if (VMI_FAILURE == vmi_read_8_va(xa->vmi, sys_va, 0, &backup_byte)) {
			printf("Failed to read byte at %" PRIx64 " for symbol %s\n", sys_va, name);
			break;
		}


		printf("Address Extracted: %s Address Converted: %" PRIx64 " Backup Byte: %" PRIx8 "\n", one_line, sys_va, backup_byte);


		if (NULL == setup_spg_bp(xa, sys_va, name, backup_byte)) {
			printf("\nFailed to add pg/bp for %s at %" PRIx64 "", name, sys_va);
			return -1;
		}
		act_calls++;

		if (act_calls == MAX_CALLS-1) //max syscalls that we want to monitor
			break;

	}//while ends

	fclose(input_file);

	return 0;

}


static void clean_xen_monitor(nif_xen_monitor* xa)
{

	if (xa->xcx)
		if (0 != libxl_ctx_free(xa->xcx))
			printf("Failed to close xl handle\n");


	if (xa->xci)
		if (0!= xc_interface_close(xa->xci))
			printf("Failed to close connection to xen interface\n");

//	xc_domain_setmaxmem(xa->xci, xa->domain_id, xa->orig_mem_size);



}

static void destroy_views(nif_xen_monitor* xa, uint32_t domain_id)
{

	if (0!= xc_altp2m_switch_to_view(xa->xci, domain_id, 0))
		printf("Failed to switch to exe view in func destroy_view\n");

	if (exe_view )
		xc_altp2m_destroy_view(xa->xci, domain_id, exe_view);

	if (0!= xc_altp2m_set_domain_state(xa->xci, domain_id, 0))
		printf("Failed to disable alternate view for domain_id: %u\n",domain_id);


}



static int inst_xen_monitor(nif_xen_monitor* xa, const char* name)
{
	if (0 == (xa->xci = xc_interface_open(NULL, NULL, 0))) {
		printf("Failed to open xen interface\n");
		return -1; // nothing to clean
	}



	if (libxl_ctx_alloc(&xa->xcx, LIBXL_VERSION, 0, NULL)) {
		printf("Unable to create xl context\n");
		goto clean;
	}


	if ( libxl_name_to_domid(xa->xcx, name, &xa->domain_id)) {
		printf("Unable to get domain id for %s\n", name);
		goto clean;
	}

	if (0 == (xa->orig_mem_size = vmi_get_memsize(xa->vmi))) {
		printf("Failed to get domain memory size\n");
		goto clean;
	}



	if (xc_domain_maximum_gpfn(xa->xci, xa->domain_id, &xa->max_gpfn) < 0) {
		printf("Failed to get max gpfn for the domain\n");
		goto clean;
	}

	//printf("\nMax gfn:%" PRIx64 "",xa->max_gpfn);



	return 1;

clean:

	clean_xen_monitor(xa);

	return -1;
}

static event_response_t
cr3_cb(vmi_instance_t vmi, vmi_event_t* event)
{


	event->x86_regs->cr3 = event->reg_event.value;

	//Flush process_related caches for clean start and consistency

	vmi_symcache_flush(vmi);
	vmi_pidcache_flush(vmi);
	vmi_v2pcache_flush(vmi, event->reg_event.previous);
	vmi_rvacache_flush(vmi);


	return VMI_EVENT_RESPONSE_NONE;
}


static event_response_t
mem_intchk_cb (vmi_instance_t vmi, vmi_event_t* event)
{



	printf("\nIntegrity check served\n");

	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	       | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}


//static void
//comms_request_listener_thread (void * args)
static void*
comms_request_listener_thread (void* args)
{
	int rc = 0;

	void* subscriber = zmq_socket (zmq_context, ZMQ_PAIR);
	if (NULL == subscriber) {
		rc = zmq_errno();
		fprintf(stderr, "zmq_socket() failed");
		goto exit;
	}

	zmq_connect (subscriber, ZMQ_REQUEST_CHANNEL);

	while (true) {
		char msg[30] = {0};
		vmi_pid_t pid = -1;

		//char * str = zstr_recv(subscriber);
		/*
		if (NULL == str) {
			fprintf (stderr, "Received empty string. All done.\n");
			break;
		}
		*/


		rc = zmq_recv (subscriber, msg, sizeof(msg), 0);
		if (rc <= 0) {
			fprintf (stderr, "Received empty string. All done.\n");
			break;
		}
		//pid = strtoul (msg, NULL, 0);

		pid = *(vmi_pid_t*) msg;
		printf ("received raw pid --> %d\n", pid);

		//free (str);
	}

exit:
	return;
}

static void
comms_fini(void)
{
	if (zmq_event_socket)  zmq_close (zmq_event_socket);


	if (zmq_context) zmq_ctx_destroy (zmq_context);

	pthread_join (pth_request_servicer, NULL);

	if (zmq_request_socket)  zmq_close (zmq_request_socket);

	zmq_context = NULL;
	zmq_event_socket  = NULL;
	zmq_request_socket  = NULL;
}

static int
comms_init(void)
{
	int rc = 0;

	zmq_context = zmq_ctx_new();
	if (NULL == zmq_context) {
		rc = errno;
		fprintf(stderr, "zmq_ctx_new() failed\n");
		goto exit;
	}

	zmq_event_socket  = zmq_socket (zmq_context, ZMQ_PUSH);
	if (NULL == zmq_event_socket) {
		rc = zmq_errno();
		fprintf(stderr, "zmq_socket() failed");
		goto exit;
	}

//    rc = zmq_connect (zmq_event_socket, ZMQ_EVENT_CHANNEL);
	rc = zmq_bind (zmq_event_socket, ZMQ_EVENT_CHANNEL);
	if (rc) {
		fprintf (stderr, "zmq_connect(" ZMQ_EVENT_CHANNEL ") failed: %d\n", rc);
		goto exit;
	}
	/*
	zmq_request_socket  = zmq_socket (zmq_context, ZMQ_PAIR);
	rc = zmq_connect (zmq_request_socket, ZMQ_REQUEST_CHANNEL);
	if (rc) {
	fprintf (stderr, "zmq_connect(" ZMQ_REQUEST_CHANNEL ") failed: %d\n", rc);
	goto exit;
	}
	*/
	//zmq_threadstart (comms_request_listener_thread, NULL);

	rc = pthread_create (&pth_request_servicer, NULL, comms_request_listener_thread, NULL);
	if (rc) {
		fprintf (stderr, "pthread_create() failed\n");
		goto exit;
	}

exit:
	return rc;
}


int main(int argc, char** argv)
{

	if (argc != 3) {
		printf("Usage: %s <domain name> <path to system_map>\n", argv[0]);
		return 1;
	}

	status_t status;
	const char* name = argv[1];
	const char* in_path = argv[2];
	nif_xen_monitor xa;
	vmi_event_t trap_event, mem_event, cr3_event;
	int rc = 0;

	/* Handle ctrl+c properly */
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	rc = comms_init();
	if (rc) {
		return -1;
	}


	// Initialize the libvmi library.
	if (VMI_FAILURE ==
	    vmi_init_complete(&xa.vmi, (void*)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS,NULL,
	                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
		printf("Failed to init LibVMI library.\n");
		goto graceful_exit;
	}

	if (-1 == inst_xen_monitor(&xa, name))
		return -1;


	printf("\n\t\t\tNumen Introspection Framework v2.0\n\n");


	xa.pframe_sframe_mappings = g_hash_table_new(NULL, NULL);
	xa.shadow_pnode_mappings = g_hash_table_new_full(NULL, NULL,NULL,free_nif_page_node);


	vmi_pause_vm(xa.vmi);

	if (0!= xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 1)) {
		printf("Failed to enable altp2m for domain_id: %u\n", xa.domain_id);
		goto graceful_exit;
	}

	if (0!= xc_altp2m_create_view(xa.xci, xa.domain_id, 0, &exe_view)) {
		printf("Failed to create execute view\n");
		goto graceful_exit;
	}


	if (0!= xc_altp2m_switch_to_view(xa.xci, xa.domain_id, exe_view)) {
		printf("Failed to switch to execute view id:%u\n", exe_view);
		goto graceful_exit;
	}

	printf("\nAltp2m: exe_view created and activated");


	//Setup a generic mem_access event.
	SETUP_MEM_EVENT(&mem_event,0,
	                VMI_MEMACCESS_RWX,
	                mem_intchk_cb,1);

	if (VMI_SUCCESS !=vmi_register_event(xa.vmi, &mem_event)) {
		printf("Failed to setup memory event\n");
		goto graceful_exit;
	}

	if (0 != inst_syscall(&xa, in_path))
		goto graceful_exit;


	if (-1 == setup_ss_events(xa.vmi))
		goto graceful_exit;


	//SETUP_INTERRUPT_EVENT(&trap_event, hook_cb);
	SETUP_INTERRUPT_EVENT(&trap_event, 0, hook_cb);
	trap_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event(xa.vmi, &trap_event)) {
		printf("\nUnable to register Interrupt event");
		goto graceful_exit;
	}


	SETUP_REG_EVENT(&cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
	if (VMI_SUCCESS !=vmi_register_event(xa.vmi, &cr3_event)) {
		printf("Failed to setup cr3 event\n");
		goto graceful_exit;
	}
	vmi_register_event(xa.vmi, &cr3_event);

	printf("\nShadow memory pages created and traps activated. Monitoring now..\n\n");

	vmi_resume_vm(xa.vmi);
	while (!interrupted) {
		status = vmi_events_listen(xa.vmi,500);
		if (status != VMI_SUCCESS) {
			printf("Some issue in the event_listen loop. Aborting!\n\n");
			interrupted = -1;
		}
	}


graceful_exit:

	vmi_pause_vm(xa.vmi);

	destroy_views(&xa, xa.domain_id);

	clean_xen_monitor(&xa);

	vmi_resume_vm(xa.vmi);

	vmi_destroy(xa.vmi);

	comms_fini();

	fflush(stdout);
	g_hash_table_destroy(xa.shadow_pnode_mappings);
	g_hash_table_destroy(xa.pframe_sframe_mappings);

	return 0;
}

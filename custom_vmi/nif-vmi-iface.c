/**
 * Description: Abstraction layer above libvmi and single-step
 *              techniques for ARM and x86. Allows user to register
 *              callbacks on either first or second event.
 *
 * Company: Numen Inc.
 *
 * Developerd: Ali Islam
 *             Matt Leinhos
 */


#include "nvmi-iface.h"

#if defined(ARM64)

static int act_calls = 0;
uint16_t sm1_view;
static uint32_t trap_arm = 0xD4000003;

#else

static vmi_event_t ss_event[MAX_VCPUS];
static int act_calls = 0;
uint16_t exe_view;
static uint8_t trap_cc = 0xCC;

#endif



static nif_xen_monitor xa;

static void
free_pg_hks_lst (gpointer data)
{
	nif_hook_node *hook_node = data;

#if defined(ARM64)
	vmi_write_8_pa (hook_node->parent->xa->vmi,
			(hook_node->parent->shadow_frame << PG_OFFSET_BITS) + hook_node->offset,
			&hook_node->backup_byte);
#else
	vmi_write_32_pa (hook_node->parent->xa->vmi,
			 (hook_node->parent->shadow_frame << PG_OFFSET_BITS) + hook_node->offset,
			 &hook_node->backup_smc1);

	vmi_write_32_pa (hook_node->parent->xa->vmi,
			 (hook_node->parent->frame << PG_OFFSET_BITS) + hook_node->offset +4,
			 &hook_node->backup_smc2);
#endif
	g_free(hook_node);
}


static void
free_nif_page_node (gpointer data)
{
	nif_page_node *pnode = data;

	g_hash_table_destroy(pnode->offset_bp_mappings);

	// Stop monitoring
	vmi_set_mem_event(pnode->xa->vmi,
			  pnode->shadow_frame,
			  VMI_MEMACCESS_N,
#if defined(ARM64)
			  sm1_view
#else
			  exe_view
#endif
		);

#if defined(ARM64)
	xc_altp2m_change_gfn (pnode->xa->xci, pnode->xa->domain_id,sm1_view,pnode->frame,~(0UL));
	xc_altp2m_change_gfn (pnode->xa->xci, pnode->xa->domain_id,sm1_view,pnode->shadow_frame,~(0UL));
#else
	xc_altp2m_change_gfn (pnode->xa->xci, pnode->xa->domain_id,exe_view,pnode->frame,~(0UL));
	xc_altp2m_change_gfn (pnode->xa->xci, pnode->xa->domain_id,exe_view,pnode->shadow_frame,~(0UL));
#endif
	
	xc_domain_decrease_reservation_exact(pnode->xa->xci,
					     pnode->xa->domain_id,
					     1, 0,
					     (xen_pfn_t*)&pnode->shadow_frame);

	g_free(pnode);
}


static nif_hook_node *
setup_spg_bp (nif_xen_monitor *xa, addr_t va, const char *name, uint32_t backup_val1, uint32_t backup_val2)
{

	size_t ret;
	status_t status;
	nif_page_node  *pgnode_new  = NULL;
	nif_hook_node *bp_new = NULL;
	addr_t pa, frame, shadow, shadow_offset;
	uint8_t buff[DOM_PAGE_SIZE] = {0};
	addr_t dtb = 0;

	if (VMI_FAILURE == vmi_pid_to_dtb(xa->vmi, 0, &dtb)){
		printf("Shadow: Couldn't get dtb\n");
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

	// Allocate frame if not already there
	if (0 == shadow)
	{
		shadow = ++(xa->max_gpfn);

		if (xc_domain_populate_physmap_exact(xa->xci, xa->domain_id, 1, 0,0, (xen_pfn_t*)&shadow) < 0) {

			printf("Failed to allocate frame at %" PRIx64 "\n", shadow);
			goto done;
		}

		g_hash_table_insert (xa->pframe_sframe_mappings, //create new translation
				     GSIZE_TO_POINTER(frame),
				     GSIZE_TO_POINTER(shadow));

		// Update p2m mapping
		if (0 != xc_altp2m_change_gfn(xa->xci, xa->domain_id, sm1_view, frame ,shadow)){
			printf("Shadow: Unable to change mapping for sm1_view\n");
			goto done;
		}
	}

	pgnode_new = g_hash_table_lookup(xa->shadow_pnode_mappings, GSIZE_TO_POINTER(shadow));
	if (NULL == pgnode_new)
	{
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

#if defined(ARM64)
	bp_new->backup_smc1 = backup_val1;
	bp_new->backup_smc2 = backup_val2;
#else
	bp_new->backup_byte = (uint8_t) backup_val1;
#endif
	strncpy(bp_new->name, name, MAX_SNAME_LEN);
	bp_new->parent     = pgnode_new;

#if defined(ARM64)
	status = vmi_write_32_pa(xa->vmi,
				 (shadow << PG_OFFSET_BITS) + shadow_offset,
				 &trap_arm);
	if (VMI_SUCCESS != status) {
		printf ("Failed to write SMC #1");
		goto done;
	}
	status = vmi_write_32_pa(xa->vmi,
				 (frame << PG_OFFSET_BITS) + shadow_offset +4, //write the second smc to orig view
				 &trap_arm);
	if (VMI_SUCCESS != status) {
		printf ("Failed to write SMC #2");
		goto done;
	}

#else
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



#if !defined(ARM64)

event_response_t singlestep_cb(vmi_instance_t vmi, vmi_event_t *event)
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

	for (int i = 0; i < vcpus; i++)	{
		SETUP_SINGLESTEP_EVENT(&ss_event[i], 1u << i, singlestep_cb,0);

		if (VMI_SUCCESS != vmi_register_event(vmi, &ss_event[i])) {
			printf("Failed to register SS event on VCPU failed %d\n", i);
			return -1;
		}
	}

	return 1;
}
#endif


void
nvmi_fini(void)
{
	vmi_pause_vm(xa.vmi);

	fflush(stdout);
	g_hash_table_destroy(xa.shadow_pnode_mappings);
	g_hash_table_destroy(xa.pframe_sframe_mappings);

	destroy_views(&xa, xa.domain_id);

	clean_xen_monitor(&xa);

	vmi_resume_vm(xa.vmi);

	vmi_destroy(xa.vmi);
}


status_t
nvmi_init()
{
	status_t status;
	vmi_event_t trap_event, mem_event, cr3_event;

	// Initialize the libvmi library.
	if (VMI_FAILURE ==
	    vmi_init_complete(&xa.vmi, (void *)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS,NULL,
			      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
		printf("Failed to init LibVMI library.\n");
		goto graceful_exit;
	}

	if(-1 == inst_xen_monitor(&xa, name))
		return -1;

	printf("\n\t\t\tNumen Introspection Framework v2.0\n\n");

	xa.pframe_sframe_mappings = g_hash_table_new(NULL, NULL);
	xa.shadow_pnode_mappings = g_hash_table_new_full(NULL, NULL,NULL,free_nif_page_node);

	vmi_pause_vm(xa.vmi);

	if(0!= xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 1)){
		printf("Failed to enable altp2m for domain_id: %u\n", xa.domain_id);
		goto graceful_exit;
	}

#if defined(ARM64)
	if (0 != xc_altp2m_create_view(xa.xci, xa.domain_id, 0, &sm1_view)) {
		printf("Failed to create smc1 view\n");
		goto graceful_exit;
	}


	if (0!= xc_altp2m_switch_to_view(xa.xci, xa.domain_id, sm1_view)) {
		printf("Failed to switch to smc1 view id:%u\n", sm1_view);
		goto graceful_exit;
	}

	printf("\nAltp2m: sm1_view created and activated");
#else

	if(0!= xc_altp2m_create_view(xa.xci, xa.domain_id, 0, &exe_view)) {
		printf("Failed to create execute view\n");
		goto graceful_exit;
	}


	if(0!= xc_altp2m_switch_to_view(xa.xci, xa.domain_id, exe_view)) {
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
#endif

graceful_exit:
	return status;
}

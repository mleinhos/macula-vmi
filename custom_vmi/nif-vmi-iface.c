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


#include "nif-vmi-iface.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>
////#include "nvmi.h"
#include <assert.h>
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


typedef uint16_t p2m_view_t;
#define ALTP2M_INVALID_VIEW (p2m_view_t)(~0)

#if defined(ARM64)

typedef uint32_t trap_val_t;
static trap_val_t trap =  0xD4000003;

// Don't reinject on ARM: SMC is not available to guest
#define INTERRUPT_REINJECT_VAL 0

#else

static vmi_event_t ss_event[MAX_VCPUS];
typedef uint8_t trap_val_t;
static trap_val_t trap = 0xcc;
#define INTERRUPT_REINJECT_VAL 1

#endif

static int act_calls = 0;
static bool interrupted = false;

static p2m_view_t alt_view1 = ALTP2M_INVALID_VIEW;

// Track Xen-wide state
typedef struct {
	libxl_ctx* xcx;
	xc_interface* xci;
	uint32_t domain_id;
	vmi_instance_t vmi;

	uint64_t orig_mem_size;
	xen_pfn_t max_gpfn;

	GHashTable* pframe_sframe_mappings; //key:pframe

	GHashTable* shadow_pnode_mappings; //key:shadow

} nif_xen_monitor; // To avoid double pointers

// Track one page containing instrumentation point
typedef struct nif_page_node {
	addr_t		frame;
	addr_t		shadow_frame;
	GHashTable* 	offset_bp_mappings; // key:offset
//	nif_xen_monitor	*xa;
} nif_page_node;

// Track one hook (instrumentation point)
typedef struct nif_hook_node {
	addr_t			offset;
	char 			name[MAX_SNAME_LEN];
	nif_page_node*		parent;

	nif_event_callback_t	pre_cb;
	nif_event_callback_t	post_cb;
	void* 			cb_arg;

	trap_val_t             backup_val1;
#if defined(ARM64)
	trap_val_t             backup_val2;
#endif
} nif_hook_node;

static nif_hook_node* vcpu_hook_nodes[MAX_VCPUS];


static nif_xen_monitor xa;

static inline status_t
write_trap_val_va (vmi_instance_t vmi, addr_t va, trap_val_t val)
{
	return vmi_write_va (vmi, va, 0, sizeof(trap_val_t), &val, NULL);
}

static inline status_t
write_trap_val_pa (vmi_instance_t vmi, addr_t pa, trap_val_t val)
{
	return vmi_write_pa (vmi, pa, sizeof(trap_val_t), &val, NULL);
}

static inline status_t
read_trap_val_va (vmi_instance_t vmi, addr_t va, trap_val_t* val)
{
	return vmi_read_va (vmi, va, 0, sizeof(trap_val_t), val, NULL);
}


static void
free_pg_hks_lst (gpointer data)
{
	nif_hook_node* hook_node = data;

	(void) write_trap_val_pa (xa.vmi,
	                          (hook_node->parent->shadow_frame << PG_OFFSET_BITS) + hook_node->offset,
	                          hook_node->backup_val1);
#if defined(ARM64)
	(void) write_trap_val_pa (xa.vmi,
	                          (hook_node->parent->shadow_frame << PG_OFFSET_BITS) + hook_node->offset + 4,
	                          hook_node->backup_val2);
#endif
	g_free(hook_node);
}

#if defined(ARM64)

/**
 * _internal_hook_cb() for ARM64
 *
 * The main callback for Xen events. In turn, calls registered callbacks above this layer.
 */
static event_response_t
_internal_hook_cb (vmi_instance_t vmi, vmi_event_t* event)
{
	nif_page_node* pgnode_temp = NULL;
	nif_hook_node* hook_node = NULL;
	addr_t shadow = 0;

	if (event->slat_id == 0) { //sw single step
		event->slat_id = sm1_view;

		// TODO: track post CBs on a per-vcpu basis and call appropriate one

		return (VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
	}

	// lookup the gfn -- do we know about it?

	shadow = (addr_t) GPOINTER_TO_SIZE(
	                 g_hash_table_lookup(xa.pframe_sframe_mappings,
	                                     GSIZE_TO_POINTER(event->privcall_event.gfn)));
	if (0 == shadow) {
		event->interrupt_event.reinject = INTERRUPT_REINJECT_VAL;
		return VMI_EVENT_RESPONSE_NONE;
	}

	pgnode_temp = g_hash_table_lookup(xa.shadow_pnode_mappings,
	                                  GSIZE_TO_POINTER(shadow));
	if (NULL == pgnode_temp) {
		fprintf(stderr, "Can't find pg_node for shadow: %" PRIx64 "\n", shadow);
		return VMI_EVENT_RESPONSE_NONE;
	}

	hook_node = g_hash_table_lookup(pgnode_temp->offset_bp_mappings,
	                                GSIZE_TO_POINTER(event->privcall_event.offset));
	if (NULL == pgnode_temp) {
		fprintf(stderr,"\nhook_cb Warning: No BP record found for this offset %" PRIx64 " on page %" PRIx16 "",
		        event->privcall_event.offset, event->privcall_event.gfn);
		event->interrupt_event.reinject = INTERRUPT_REINJECT_VAL;
		return VMI_EVENT_RESPONSE_NONE;
	}

	// Otherwise, we found the hook node
	if (hook_node->pre_cb) {
		hook_node->pre_cb (vmi, event, hook_node->cb_arg);
	}

	vcpu_hook_nodes [event->vcpu_id] = hook_node;
exit:

	if (event->slat_id == sm1_view) {
		event-> slat_id = 0;
	}

	return (VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

#else

/**
 * _internal_hook_cb() for Intel
 *
 * The main callback for Xen events. In turn, calls registered callbacks above this layer.
 */
static event_response_t
_internal_hook_cb (vmi_instance_t vmi, vmi_event_t* event)
{
	nif_page_node* pgnode_temp = NULL;
	nif_hook_node* hook_node = NULL;
	addr_t shadow = 0;

	// lookup the gfn -- do we know about it?
	shadow = (addr_t) GPOINTER_TO_SIZE(
	                 g_hash_table_lookup(xa.pframe_sframe_mappings,
	                                     GSIZE_TO_POINTER(event->interrupt_event.gfn)));

	if (0 == shadow) {
		event->interrupt_event.reinject = INTERRUPT_REINJECT_VAL;
		return VMI_EVENT_RESPONSE_NONE;
	}

	pgnode_temp = g_hash_table_lookup(xa.shadow_pnode_mappings,
	                                  GSIZE_TO_POINTER(shadow));
	if (NULL == pgnode_temp) {
		fprintf(stderr, "Can't find pg_node for shadow: %" PRIx64 "\n", shadow);
		return VMI_EVENT_RESPONSE_NONE;
	}

	hook_node = g_hash_table_lookup(pgnode_temp->offset_bp_mappings,
	                                GSIZE_TO_POINTER(event->interrupt_event.offset));
	if (NULL == pgnode_temp) {
		fprintf(stderr,"Can't find pg_node for shadow: %" PRIx64 "\n", shadow);
		event->interrupt_event.reinject = INTERRUPT_REINJECT_VAL;
		return VMI_EVENT_RESPONSE_NONE;
	}

	// Otherwise, we found the hook node
	if (hook_node->pre_cb) {
		hook_node->pre_cb (vmi, event, hook_node->cb_arg);
	}

	vcpu_hook_nodes [event->vcpu_id] = hook_node;

exit:
	event->interrupt_event.reinject = 0;
	event-> slat_id = 0;
	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP|
	        VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}
#endif // ARM64

static void
free_nif_page_node (gpointer data)
{
	nif_page_node* pnode = data;

	g_hash_table_destroy(pnode->offset_bp_mappings);

	// Stop monitoring
	vmi_set_mem_event(xa.vmi,
	                  pnode->shadow_frame,
	                  VMI_MEMACCESS_N,
	                  alt_view1 );

	xc_altp2m_change_gfn (xa.xci, xa.domain_id,alt_view1,pnode->frame,~(0UL));
	xc_altp2m_change_gfn (xa.xci, xa.domain_id,alt_view1,pnode->shadow_frame,~(0UL));

	xc_domain_decrease_reservation_exact(xa.xci,
	                                     xa.domain_id,
	                                     1, 0,
	                                     (xen_pfn_t*)&pnode->shadow_frame);
	g_free(pnode);
}

int
nif_enable_monitor (addr_t kva,
                    const char* name,
                    nif_event_callback_t pre_cb,
                    nif_event_callback_t post_cb,
                    void* cb_arg)
{
	int rc = 0;
	size_t ret;
	status_t status;
	nif_page_node*  pgnode_new  = NULL;
	nif_hook_node* hook_node = NULL;
	addr_t pa, frame;
	addr_t shadow, shadow_frame, shadow_offset;
	uint8_t buff[DOM_PAGE_SIZE] = {0};
	addr_t dtb = 0;

	if (VMI_FAILURE == vmi_pid_to_dtb (xa.vmi, 0, &dtb)) {
		rc = EINVAL;
		assert (!"vmi_pid_to_dtb()");
		fprintf(stderr,"Shadow: Couldn't get dtb\n");
		goto done;
	}

	if (VMI_SUCCESS != vmi_pagetable_lookup (xa.vmi,dtb, kva, &pa)) {
		rc = EINVAL;
		assert (!"vmi_pagetable_lookup()");
		fprintf(stderr,"Shadow: Couldn't get pagetable information\n");
		goto done;
	}

	frame = pa >> PG_OFFSET_BITS;

	shadow_offset = pa % DOM_PAGE_SIZE;
	shadow_frame = (addr_t) GPOINTER_TO_SIZE (g_hash_table_lookup(xa.pframe_sframe_mappings,
	                                    GSIZE_TO_POINTER(frame)));

	// Allocate frame if not already there
	if (0 == shadow_frame) {
		shadow_frame = ++(xa.max_gpfn);

		if (xc_domain_populate_physmap_exact(xa.xci, xa.domain_id, 1, 0,0, (xen_pfn_t*)&shadow_frame) < 0) {
			rc = ENOMEM;
			assert (!"xc_domain_populate_physmap_exact()");
			fprintf(stderr,"Failed to allocate frame at %" PRIx64 "\n", shadow_frame);
			goto done;
		}

		g_hash_table_insert (xa.pframe_sframe_mappings, //create new translation
		                     GSIZE_TO_POINTER(frame),
		                     GSIZE_TO_POINTER(shadow_frame));

		// Update p2m mapping
		if (0 != xc_altp2m_change_gfn(xa.xci, xa.domain_id, alt_view1, frame, shadow_frame)) {
			rc = EACCES;
			assert (!"xc_altp2m_change_gfn()");
			fprintf(stderr,"Shadow: Unable to change mapping for alt_view1\n");
			goto done;
		}
	}

	pgnode_new = g_hash_table_lookup(xa.shadow_pnode_mappings, GSIZE_TO_POINTER(shadow_frame));
	if (NULL == pgnode_new) {
		status = vmi_read_pa(xa.vmi,
		                     frame << PG_OFFSET_BITS,
		                     DOM_PAGE_SIZE,
		                     buff,
		                     &ret);
		if (DOM_PAGE_SIZE!= ret || status == VMI_FAILURE) {
			rc = EACCES;
			assert (!"vmi_read_pa()");
			fprintf(stderr,"Shadow: Failed to read syscall page\n");
			goto done;
		}

		status = vmi_write_pa(xa.vmi,
		                      shadow_frame << PG_OFFSET_BITS,
		                      DOM_PAGE_SIZE,
		                      buff,
		                      &ret);
		if (DOM_PAGE_SIZE!= ret || status == VMI_FAILURE) {
			rc = EACCES;
			assert (!"vmi_write_pa()");
			fprintf(stderr,"Shadow: Failed to write to shadow page\n");
			goto done;
		}

		// Update the hks list
		pgnode_new               = g_new0(nif_page_node, 1);
		pgnode_new->shadow_frame = shadow_frame;
		pgnode_new->frame        = frame;
		pgnode_new->offset_bp_mappings = g_hash_table_new_full(NULL, NULL,NULL,free_pg_hks_lst);

		g_hash_table_insert(xa.shadow_pnode_mappings,
		                    GSIZE_TO_POINTER(shadow_frame),
		                    pgnode_new);
#if 0
		// Activate monitoring for this page.
		status = vmi_set_mem_event(xa.vmi,
		                           shadow_frame,
		                           VMI_MEMACCESS_RW,
		                           alt_view1);
		if (VMI_SUCCESS != status) {
			rc = EACCES;
			assert (!"vmi_set_mem_event()");
			fprintf(stderr,"Shadow: Couldn't set frame permissions for %" PRIx64 "\n", shadow_frame);
			goto done;
		}
		//fprintf(stderr,"\nInside: Monitoring on shadow page activated");
#endif
	} else {
		// Check for existing hooks: if one exists, we're done
		hook_node = g_hash_table_lookup(pgnode_new->offset_bp_mappings,
		                             GSIZE_TO_POINTER(shadow_offset));
		if (NULL != hook_node) {
			// not an error -- we're done
			goto done;
		}
	}

	hook_node = g_new0(nif_hook_node, 1);
	shadow = (shadow_frame << PG_OFFSET_BITS) + shadow_offset;

	// TODO: experiment with the second callback: can we change it
	// to be notified on an access to schedule() / __schedule()
	// rather than the very next instruction?

	// Read and write the first value unconditionally
	if (VMI_FAILURE == read_trap_val_va (xa.vmi, kva, &hook_node->backup_val1)) {
		rc = EACCES;
		printf ("Failed to read orig val at %" PRIx64 "\n", kva);
		goto done;
	}

	if (VMI_FAILURE == write_trap_val_pa (xa.vmi, shadow, trap)) {
		rc = EACCES;
		printf ("Failed to write trap val at %" PRIx64 "\n", pa);
		goto done;
	}

	// TODO: experiment with the second callback: can we change it
	// to be notified on an access to schedule() / __schedule()
	// rather than the very next instruction? This applies to
	// Intel too -- is a second #VE faster than single stepping?

	// In the case of ARM, read/write the second value too
#if defined(ARM64)
	if (VMI_FAILURE == read_trap_val_va (xa.vmi, kva+4, &hook_node->backup_val2)) {
		rc = EACCES;
		printf ("Failed to read orig val at %" PRIx64 "\n", kva+4);
		goto done;
	}

	if (VMI_FAILURE == write_trap_val_pa (xa.vmi, shadow + 4, trap)) {
		rc = EACCES;
		printf ("Failed to write trap val at %" PRIx64 "\n", pa + 4);
		goto done;
	}
#endif

	strncpy(hook_node->name, name, MAX_SNAME_LEN);
	hook_node->parent     = pgnode_new;
	hook_node->offset     = shadow_offset;

	hook_node->pre_cb     = pre_cb;
	hook_node->post_cb    = post_cb;
	hook_node->cb_arg     = cb_arg;

	g_hash_table_insert(pgnode_new->offset_bp_mappings,
	                    GSIZE_TO_POINTER(shadow_offset),
	                    hook_node);

	//fprintf(stderr,"\nInside: New bp node inserted with offset %" PRIx64 "", shadow_offset);
done:
	return rc;
}



#if !defined(ARM64)

static event_response_t
singlestep_cb(vmi_instance_t vmi, vmi_event_t* event)
{
	event->slat_id = alt_view1;

	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP|
	        VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

static int
setup_ss_events (vmi_instance_t vmi)
{
	int vcpus = vmi_get_num_vcpus(vmi);
	fprintf(stderr,"\nDomain vcpus=%d", vcpus);

	if (0 == vcpus) {
		fprintf(stderr,"Failed to find the total VCPUs\n");
		return -1;
	}

	if (vcpus > MAX_VCPUS) {
		fprintf(stderr,"Guest VCPUS are greater than what we can support\n");
		return -1;
	}

	for (int i = 0; i < vcpus; i++) {
		SETUP_SINGLESTEP_EVENT(&ss_event[i], 1u << i, singlestep_cb,0);

		if (VMI_SUCCESS != vmi_register_event(vmi, &ss_event[i])) {
			fprintf(stderr,"Failed to register SS event on VCPU failed %d\n", i);
			return -1;
		}
	}

	return 1;
}
#endif

#if !defined(ARM64)

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
	fprintf(stderr,"\nIntegrity check served\n");

	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	       | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}
#endif


static void clean_xen_monitor(void)
{
	if (xa.xcx)
		if (0 != libxl_ctx_free(xa.xcx))
			fprintf(stderr,"Failed to close xl handle\n");

	if (xa.xci)
		if (0!= xc_interface_close(xa.xci))
			fprintf(stderr,"Failed to close connection to xen interface\n");

//	xc_domain_setmaxmem(xa->xci, xa->domain_id, xa->orig_mem_size);
}


static void destroy_views(uint32_t domain_id)
{
	if (0!= xc_altp2m_switch_to_view(xa.xci, domain_id, 0))
		fprintf(stderr,"Failed to switch to exe view in func destroy_view\n");

	if (alt_view1 )
		xc_altp2m_destroy_view(xa.xci, domain_id, alt_view1);

	if (0!= xc_altp2m_set_domain_state(xa.xci, domain_id, 0))
		fprintf(stderr,"Failed to disable alternate view for domain_id: %u\n",domain_id);
}

static int inst_xen_monitor(const char* name)
{
	if (0 == (xa.xci = xc_interface_open(NULL, NULL, 0))) {
		fprintf(stderr,"Failed to open xen interface\n");
		return -1; // nothing to clean
	}



	if (libxl_ctx_alloc(&xa.xcx, LIBXL_VERSION, 0, NULL)) {
		fprintf(stderr,"Unable to create xl context\n");
		goto clean;
	}


	if ( libxl_name_to_domid(xa.xcx, name, &xa.domain_id)) {
		fprintf(stderr,"Unable to get domain id for %s\n", name);
		goto clean;
	}

	if (0 == (xa.orig_mem_size = vmi_get_memsize(xa.vmi))) {
		fprintf(stderr,"Failed to get domain memory size\n");
		goto clean;
	}



	if (xc_domain_maximum_gpfn(xa.xci, xa.domain_id, &xa.max_gpfn) < 0) {
		fprintf(stderr,"Failed to get max gpfn for the domain\n");
		goto clean;
	}

	//fprintf(stderr,"\nMax gfn:%" PRIx64 "",xa.max_gpfn);
	return 1;

clean:
	clean_xen_monitor();
	return -1;
}

void
nif_fini(void)
{
	vmi_pause_vm(xa.vmi);

	fflush(stdout);
	g_hash_table_destroy(xa.shadow_pnode_mappings);
	g_hash_table_destroy(xa.pframe_sframe_mappings);

	destroy_views(xa.domain_id);

	clean_xen_monitor();

	vmi_resume_vm(xa.vmi);

	vmi_destroy(xa.vmi);
}

// FIXME: return errno
int
nif_init(const char* name)
{
	vmi_event_t trap_event, mem_event, cr3_event;
	status_t status;

	// Initialize the libvmi library.
	if (VMI_FAILURE ==
	    vmi_init_complete(&xa.vmi, (void*)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS,NULL,
	                      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
		fprintf(stderr,"Failed to init LibVMI library.\n");
		goto graceful_exit;
	}

	if (-1 == inst_xen_monitor(name))
		return -1;

	fprintf(stderr,"\n\t\t\tNumen Introspection Framework v2.0\n\n");

	xa.pframe_sframe_mappings = g_hash_table_new(NULL, NULL);
	xa.shadow_pnode_mappings = g_hash_table_new_full(NULL, NULL,NULL,free_nif_page_node);

	vmi_pause_vm(xa.vmi);

	if (0!= xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 1)) {
		fprintf(stderr,"Failed to enable altp2m for domain_id: %u\n", xa.domain_id);
		goto graceful_exit;
	}

	if (0!= xc_altp2m_create_view(xa.xci, xa.domain_id, 0, &alt_view1)) {
		fprintf(stderr,"Failed to create execute view\n");
		goto graceful_exit;
	}


	if (0!= xc_altp2m_switch_to_view(xa.xci, xa.domain_id, alt_view1)) {
		fprintf(stderr,"Failed to switch to execute view id:%u\n", alt_view1);
		goto graceful_exit;
	}

	fprintf(stderr, "Altp2m: alt_view1 created and activated\n");

#if !defined(ARM64)
	//Setup a generic mem_access event.
	SETUP_MEM_EVENT(&mem_event,0,
	                VMI_MEMACCESS_RWX,
	                mem_intchk_cb,1);

	if (VMI_SUCCESS !=vmi_register_event(xa.vmi, &mem_event)) {
		fprintf(stderr,"Failed to setup memory event\n");
		goto graceful_exit;
	}
#endif

graceful_exit:
	return status;
}


void
nif_stop (void)
{
	interrupted = true;
}


int
nif_event_loop (void)
{
	int rc = 0;

	vmi_event_t trap_event, mem_event, cr3_event;

#if defined(ARM64)
	SETUP_PRIVCALL_EVENT(&trap_event, hook_cb);
	trap_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event(xa.vmi, &trap_event)) {
		fprintf(stderr,"\nUnable to register privcall event");
		goto exit;
	}

#else
	if (-1 == setup_ss_events(xa.vmi))
		goto exit;

	SETUP_INTERRUPT_EVENT(&trap_event, 0, _internal_hook_cb);
	trap_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event(xa.vmi, &trap_event)) {
		fprintf(stderr,"\nUnable to register Interrupt event");
		goto exit;
	}

	SETUP_REG_EVENT(&cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
	if (VMI_SUCCESS !=vmi_register_event(xa.vmi, &cr3_event)) {
		fprintf(stderr,"Failed to setup cr3 event\n");
		goto exit;
	}
	vmi_register_event(xa.vmi, &cr3_event);
#endif

	vmi_resume_vm(xa.vmi);

	while (!interrupted) {
		status_t status = vmi_events_listen(xa.vmi,500);
		if (status != VMI_SUCCESS) {
			fprintf(stderr,"Some issue in the event_listen loop. Aborting!\n\n");
			interrupted = -1;
			rc = EBUSY;
		}
	}

exit:
	return rc;
}

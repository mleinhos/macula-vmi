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
#include "nvmi-common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <setjmp.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libxl_utils.h>
#include <libxl.h>

#include <xenctrl.h>
#include <libvmi/slat.h>

#include <xenevtchn.h>
#include <xen/vm_event.h>
#include <xenctrl_compat.h>

#include <glib.h>
#include <assert.h>

#include <semaphore.h>

#include "clog.h"

typedef uint16_t p2m_view_t;
#define ALTP2M_INVALID_VIEW (p2m_view_t)(~0)

#if defined(ARM64)

typedef uint32_t trap_val_t;
static trap_val_t trap =  0xD4000003; // ARM SMC

#else

static vmi_event_t ss_event[MAX_VCPUS];
typedef uint8_t trap_val_t;
static trap_val_t trap = 0xcc; // Intel #DB

#endif

static int act_calls = 0;
static volatile bool interrupted = false;
static GThread * event_loop_thread = NULL;

static p2m_view_t alt_view1 = ALTP2M_INVALID_VIEW;

// Track Xen-wide state
typedef struct {
	libxl_ctx* xcx;
	xc_interface* xci;
	uint32_t domain_id;
	vmi_instance_t vmi;

	addr_t kdtb;

	uint64_t orig_mem_size;
	xen_pfn_t max_gpfn;

	GHashTable* pframe_sframe_mappings; //key:pframe

	GHashTable* shadow_pnode_mappings; //key:shadow

	sem_t start_loop;
	sem_t loop_complete;
	bool * ext_nif_busy;
	int loop_status;

} nif_xen_monitor; // To avoid double pointers

// Track one page containing instrumentation point
typedef struct nif_page_node {
	addr_t		frame;
	addr_t		shadow_frame;
	GHashTable* 	offset_bp_mappings; // key:offset
} nif_page_node;

// Track one hook (instrumentation point)
typedef struct nif_hook_node {
	addr_t			offset;
	char 			name[SYSCALL_MAX_NAME_LEN];
	nif_page_node*		parent;

	nif_event_callback_t	pre_cb;
	nif_event_callback_t	post_cb;
	void* 			cb_arg;

	 // orig value in shadow frame (init instr point)
	trap_val_t             backup_val1;
#if defined(ARM64)
	// orig value in orig view (secondary instr point)
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
	status_t status;

	status = write_trap_val_pa (xa.vmi,
				    MKADDR(hook_node->parent->shadow_frame, hook_node->offset),
				    hook_node->backup_val1);
#if defined(ARM64)
	status |= write_trap_val_pa (xa.vmi,
				     MKADDR(hook_node->parent->frame, hook_node->offset) + 4,
				     hook_node->backup_val2);
#endif
	if (VMI_SUCCESS != status) {
		clog_error (CLOG(CLOGGER_ID),
			    "Failed to restore original hookpoint values near PA=%" PRIx64 "",
			    MKADDR(hook_node->parent->shadow_frame, hook_node->offset));
	}

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
	nif_page_node* pgnode = NULL;
	nif_hook_node* hook_node = NULL;
	addr_t shadow = 0;

	if (event->slat_id == 0) { // SW SINGLE STEP
		event->slat_id = alt_view1;
		// TODO: track post CBs on a per-vcpu basis and call appropriate one
#if 0
		hook_node = vcpu_hook_nodes [event->vcpu_id];
		if (NULL != hook_node) {
			if (hook_node->post_cb) {
				hook_node->post_cb (hook_node->cb_arg);
			}
		}
#endif
		return (VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
	}

	// lookup the gfn -- do we know about it?

	shadow = (addr_t) GPOINTER_TO_SIZE(
		g_hash_table_lookup(xa.pframe_sframe_mappings,
				    GSIZE_TO_POINTER(event->privcall_event.gfn)));
	if (0 == shadow) {
		// No need to reinject since SMC is not available to guest
		return VMI_EVENT_RESPONSE_NONE;
	}

	pgnode = g_hash_table_lookup (xa.shadow_pnode_mappings,
				      GSIZE_TO_POINTER(shadow));
	if (NULL == pgnode) {
		clog_error (CLOG(CLOGGER_ID), "Can't find pg_node for shadow: %" PRIx64 "", shadow);
		return VMI_EVENT_RESPONSE_NONE;
	}

	hook_node = g_hash_table_lookup (pgnode->offset_bp_mappings,
					 GSIZE_TO_POINTER(event->privcall_event.offset));
	if (NULL == hook_node) {
		clog_error (CLOG(CLOGGER_ID), "Warning: No BP record found for this offset %" PRIx64 " on page %" PRIx64 "",
			    event->privcall_event.offset, event->privcall_event.gfn);
		return VMI_EVENT_RESPONSE_NONE;
	}

	// Otherwise, we found the hook node
	if (hook_node->pre_cb) {
		hook_node->pre_cb (vmi, event, hook_node->cb_arg);
	}

	//vcpu_hook_nodes [event->vcpu_id] = hook_node;

	if (event->slat_id == alt_view1) {
		event->slat_id = 0;
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
	nif_page_node* pgnode = NULL;
	nif_hook_node* hook_node = NULL;
	addr_t shadow = 0;

	// lookup the gfn -- do we know about it?
	shadow = (addr_t) GPOINTER_TO_SIZE(
		g_hash_table_lookup (xa.pframe_sframe_mappings,
				     GSIZE_TO_POINTER(event->interrupt_event.gfn)));

	if (0 == shadow) {
		clog_warn (CLOG(CLOGGER_ID), "Can't find shadow for gfn=%" PRIx64 ", reinjecting.", shadow);
		event->interrupt_event.reinject = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	pgnode = g_hash_table_lookup (xa.shadow_pnode_mappings,
				      GSIZE_TO_POINTER(shadow));
	if (NULL == pgnode) {
		clog_warn (CLOG(CLOGGER_ID), "Can't find page node for shadow=%" PRIx64 ", reinjecting.", shadow);
		event->interrupt_event.reinject = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	hook_node = g_hash_table_lookup (pgnode->offset_bp_mappings,
					 GSIZE_TO_POINTER (event->interrupt_event.offset));
	if (NULL == hook_node) {
		clog_error (CLOG(CLOGGER_ID),
			    "No BP record found for this offset %" PRIx64 " on page %" PRIx64 ", reinjecting.",
			    event->interrupt_event.offset, event->interrupt_event.gfn);
		event->interrupt_event.reinject = 1;
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

	clog_debug (CLOG(CLOGGER_ID),
		    "Disabling monitoring of mfn=%" PRIx64 ", shadow=%" PRIx64,
		    pnode->frame, pnode->shadow_frame);

	if (NULL != pnode->offset_bp_mappings) {
		g_hash_table_destroy(pnode->offset_bp_mappings);
	}

	// Stop monitoring
	vmi_set_mem_event(xa.vmi,
			  pnode->shadow_frame,
			  VMI_MEMACCESS_N,
			  alt_view1);

	xc_altp2m_change_gfn (xa.xci, xa.domain_id, alt_view1, pnode->frame, ~(0UL));
	xc_altp2m_change_gfn (xa.xci, xa.domain_id, alt_view1, pnode->shadow_frame, ~(0UL));

	xc_domain_decrease_reservation_exact (xa.xci,
					      xa.domain_id,
					      1, 0,
					      (xen_pfn_t*)&pnode->shadow_frame);
	g_free (pnode);
}

int
nif_is_monitored(addr_t kva, bool * monitored)
{
	int rc = 0;
	addr_t pa, frame;
	status_t status;
	nif_page_node*  pgnode  = NULL;
	nif_hook_node* hook_node = NULL;

	addr_t shadow;
	addr_t shadow_frame, offset;

	*monitored = false;

	status = vmi_pagetable_lookup (xa.vmi, xa.kdtb, kva, &pa);
	if (VMI_SUCCESS != status) {
		rc = EINVAL;
		clog_error (CLOG(CLOGGER_ID), "Failed to find PA for kernel VA=%" PRIx64 "", kva);
		goto exit;
	}
/*
	status = vmi_translate_kv2p (xa.vmi, kva, &pa);
	if (VMI_SUCCESS != status) {
		rc = EINVAL;
		clog_error (CLOG(CLOGGER_ID), "Failed to find PA for VA=%" PRIx64 "", kva);
		goto exit;
	}
*/
	frame = pa >> PG_OFFSET_BITS;
	offset = pa % DOM_PAGE_SIZE;

	shadow_frame = (addr_t) GPOINTER_TO_SIZE (
		g_hash_table_lookup (xa.pframe_sframe_mappings, GSIZE_TO_POINTER(frame)));

	if (0 == shadow_frame) {
		goto exit;
	}

	pgnode = g_hash_table_lookup(xa.shadow_pnode_mappings,
				     GSIZE_TO_POINTER(shadow_frame));
	if (NULL == pgnode) {
		goto exit;
	}

	hook_node = g_hash_table_lookup(pgnode->offset_bp_mappings,
					GSIZE_TO_POINTER(offset));
	if (NULL == hook_node) {
		goto exit;
	}

	*monitored = true;

exit:
	return rc;
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
	nif_page_node * pgnode  = NULL;
	nif_hook_node * hook_node = NULL;
	addr_t pa, frame, offset;
	addr_t shadow, shadow_frame;
	uint8_t buff[DOM_PAGE_SIZE] = {0};
	addr_t dtb = 0;
	trap_val_t orig1 = 0;
#if defined(ARM64)
	trap_val_t orig2 = 0;
#endif

	// Read orig values
	status  = read_trap_val_va (xa.vmi, kva, &orig1);
#if defined(ARM64)
	status |= read_trap_val_va (xa.vmi, kva+4, &orig2);
#endif
	if (VMI_SUCCESS != status) {
		rc = EACCES;
		clog_error (CLOG(CLOGGER_ID), "Failed to read orig val near %" PRIx64 "", kva);
		goto exit;
	}

	status = vmi_pagetable_lookup (xa.vmi, xa.kdtb, kva, &pa);
	if (VMI_SUCCESS != status) {
		rc = EINVAL;
		clog_error (CLOG(CLOGGER_ID), "Failed to find PA for kernel VA=%" PRIx64 "", kva);
		goto exit;
	}

	frame = pa >> PG_OFFSET_BITS;
	offset = pa % DOM_PAGE_SIZE;

	shadow_frame = (addr_t) GPOINTER_TO_SIZE (g_hash_table_lookup(xa.pframe_sframe_mappings,
								      GSIZE_TO_POINTER(frame)));
	if (0 == shadow_frame) {
		// Allocate frame if not already there
		shadow_frame = ++(xa.max_gpfn);

		rc = xc_domain_populate_physmap_exact (xa.xci, xa.domain_id, 1, 0, 0, (xen_pfn_t*)&shadow_frame);
		if (rc < 0) {
			rc = ENOMEM;
			clog_error (CLOG(CLOGGER_ID),
				    "Failed to allocate frame at %" PRIx64 "", shadow_frame);
			goto exit;
		}

		g_hash_table_insert (xa.pframe_sframe_mappings, //create new translation
				     GSIZE_TO_POINTER(frame),
				     GSIZE_TO_POINTER(shadow_frame));

		// Update p2m mapping: alt_view1: frame --> shadow_frame
		rc = xc_altp2m_change_gfn(xa.xci, xa.domain_id, alt_view1, frame, shadow_frame);
		if (rc) {
			rc = EACCES;
			clog_error (CLOG(CLOGGER_ID), "Shadow: Unable to change mapping for alt_view1\n");
			goto exit;
		}
	}

	// shadow_frame is now known
	clog_debug (CLOG(CLOGGER_ID), "shadow %lx shadow_frame %lx for va %lx",
		    shadow, shadow_frame, kva);

	pgnode = g_hash_table_lookup(xa.shadow_pnode_mappings, GSIZE_TO_POINTER(shadow_frame));
	if (NULL == pgnode) {
		// Copy orig frame into shadow
		status = vmi_read_pa(xa.vmi,
				     MKADDR(frame, 0),
				     DOM_PAGE_SIZE,
				     buff,
				     &ret);
		if (DOM_PAGE_SIZE != ret || status == VMI_FAILURE) {
			rc = EACCES;
			clog_error (CLOG(CLOGGER_ID), "Shadow: Failed to read target page, frame=%lx", frame);
			goto exit;
		}

		status = vmi_write_pa(xa.vmi,
				      MKADDR(shadow_frame, 0),
				      DOM_PAGE_SIZE,
				      buff,
				      &ret);
		if (DOM_PAGE_SIZE != ret || status == VMI_FAILURE) {
			rc = EACCES;
			clog_error (CLOG(CLOGGER_ID), "Shadow: Failed to write to shadow page");
			goto exit;
		}

		// Update the hks list
		pgnode               = g_new0(nif_page_node, 1);
		pgnode->shadow_frame = shadow_frame;
		pgnode->frame        = frame;
		pgnode->offset_bp_mappings = g_hash_table_new_full (NULL, NULL, NULL, free_pg_hks_lst);

		g_hash_table_insert (xa.shadow_pnode_mappings,
				     GSIZE_TO_POINTER(shadow_frame),
				     pgnode);
	} else {
		// Check for existing hooks: if one exists, we're done
		hook_node = g_hash_table_lookup (pgnode->offset_bp_mappings,
						 GSIZE_TO_POINTER(offset));
		if (NULL != hook_node) {
			clog_error (CLOG(CLOGGER_ID), "Found hook already in place for va %" PRIx64 "", kva);
			goto exit;
		}
	}

	// TODO: experiment with the second callback: can we change it
	// to be notified on an access to schedule() / __schedule()
	// rather than the very next instruction? This applies to
	// Intel too -- is a second #BP faster than single stepping?

	// Write the trap/smc value(s): The first goes in the shadow
	// page, the second (ARM only) goes in the orig page.
	clog_debug (CLOG(CLOGGER_ID), "Writing trap %x to PA (ARM: and PA+4) %" PRIx64 ", backup1=%x",
		    trap, shadow, orig1);

	status  = write_trap_val_pa (xa.vmi, MKADDR(shadow_frame, offset), trap);
#if defined(ARM64)
	status |= write_trap_val_pa (xa.vmi, MKADDR(frame,  offset) + 4, trap);
#endif
	if (VMI_SUCCESS != status) {
		rc = EACCES;
		clog_error (CLOG(CLOGGER_ID), "Failed to write trap val at orig or shadow page");
		goto exit;
	}

	// Create new hook node and save it
	hook_node = g_new0(nif_hook_node, 1);
	strncpy (hook_node->name, name, MAX_SNAME_LEN);
	hook_node->parent     = pgnode;
	hook_node->offset     = offset;
	hook_node->pre_cb     = pre_cb;
	hook_node->post_cb    = post_cb;
	hook_node->cb_arg     = cb_arg;

	hook_node->backup_val1 = orig1;
#if defined(ARM64)
	hook_node->backup_val2 = orig2;
#endif

	g_hash_table_insert(pgnode->offset_bp_mappings,
			    GSIZE_TO_POINTER(offset),
			    hook_node);
exit:
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
	int rc = 0;

	clog_info (CLOG(CLOGGER_ID), "Domain vcpus=%d", vcpus);

	if (0 == vcpus) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to find the total VCPUs");
		goto exit;
	}

	if (vcpus > MAX_VCPUS) {
		rc = EINVAL;
		clog_error (CLOG(CLOGGER_ID), "Guest VCPUS are greater than what we can support");
			goto exit;
	}

	for (int i = 0; i < vcpus; i++) {
		SETUP_SINGLESTEP_EVENT(&ss_event[i], 1u << i, singlestep_cb,0);

		if (VMI_SUCCESS != vmi_register_event(vmi, &ss_event[i])) {
			rc = EIO;
			clog_error (CLOG(CLOGGER_ID), "Failed to register SS event on VCPU failed %d", i);
			goto exit;
		}
	}
exit:
	return rc;
}
#endif

#if !defined(ARM64)

static event_response_t
cr3_cb(vmi_instance_t vmi, vmi_event_t* event)
{
	event->x86_regs->cr3 = event->reg_event.value;

	// Flush process_related caches for clean start and
	// consistency

	// TODO: optimize this - perhaps just flush in event
	// callbacks, when user memory will be interrogated

	vmi_symcache_flush(vmi);
	vmi_pidcache_flush(vmi);
	vmi_v2pcache_flush(vmi, event->reg_event.previous);
	vmi_rvacache_flush(vmi);

	return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t
mem_intchk_cb (vmi_instance_t vmi, vmi_event_t* event)
{
	clog_info (CLOG(CLOGGER_ID), "\nIntegrity check served\n");

	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	       | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}
#endif


static void fini_xen_monitor(void)
{
	if (xa.xcx) {
		if (0 != libxl_ctx_free(xa.xcx)) {
			clog_error (CLOG(CLOGGER_ID), "Failed to close xl handle\n");
		}
		xa.xcx = NULL;
	}

	if (xa.xci) {
		if (0 != xc_interface_close(xa.xci)) {
			clog_error (CLOG(CLOGGER_ID), "Failed to close connection to xen interface\n");
		}
		xa.xci = NULL;
	}
}


static void destroy_views(uint32_t domain_id)
{
	if (NULL == xa.xci) {
		return;
	}

	if (0 != xc_altp2m_switch_to_view(xa.xci, domain_id, 0))
		clog_error (CLOG(CLOGGER_ID), "Failed to switch to exe view in func destroy_view");

	if (alt_view1)
		xc_altp2m_destroy_view(xa.xci, domain_id, alt_view1);

	if (0 != xc_altp2m_set_domain_state(xa.xci, domain_id, 0))
		clog_error (CLOG(CLOGGER_ID), "Failed to disable alternate view for domain_id: %u",domain_id);
}


static int
init_xen_monitor(const char* name)
{
	int rc = 0;
	if (0 == (xa.xci = xc_interface_open(NULL, NULL, 0))) {
		clog_error (CLOG(CLOGGER_ID), "Failed to open xen interface\n");
		return EIO; // nothing to clean
	}

	if (libxl_ctx_alloc(&xa.xcx, LIBXL_VERSION, 0, NULL)) {
		rc = ENOMEM;
		clog_error (CLOG(CLOGGER_ID), "Unable to create xl context\n");
		goto clean;
	}


	if ( libxl_name_to_domid(xa.xcx, name, &xa.domain_id)) {
		rc = EINVAL;
		clog_error (CLOG(CLOGGER_ID), "Unable to get domain id for %s\n", name);
		goto clean;
	}

	if (0 == (xa.orig_mem_size = vmi_get_memsize(xa.vmi))) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to get domain memory size\n");
		goto clean;
	}

	if (xc_domain_maximum_gpfn(xa.xci, xa.domain_id, &xa.max_gpfn) < 0) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to get max gpfn for the domain\n");
		goto clean;
	}

	//clog_info (CLOG(CLOGGER_ID), "\nMax gfn:%" PRIx64 "",xa.max_gpfn);
	return 0;

clean:
	fini_xen_monitor();
	return rc;
}


static void *
nif_event_loop_worker (void * arg)
{
	int rc = 0;
	vmi_event_t main_event;
	//vmi_event_t cr3_event;

	*xa.ext_nif_busy = true;

	sem_wait (&xa.start_loop);

	if (interrupted)
	{
		goto exit;
	}

	clog_info (CLOG(CLOGGER_ID), "Starting VMI event loop");

#if defined(ARM64)
	SETUP_PRIVCALL_EVENT(&main_event, _internal_hook_cb);
	main_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event(xa.vmi, &main_event)) {
		clog_error (CLOG(CLOGGER_ID), "Unable to register privcall event");
		goto exit;
	}
#else
	rc = setup_ss_events(xa.vmi);
	if (rc) {
		goto exit;
	}

	SETUP_INTERRUPT_EVENT (&main_event, 0, _internal_hook_cb);
	main_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event (xa.vmi, &main_event)) {
		clog_error (CLOG(CLOGGER_ID), "Unable to register interrupt event");
		goto exit;
	}

#if 0
	// Not necessary: If we don't trust the user address space
	// cache on a callback, we should invalidate it in the
	// callback and not add another callback!
	SETUP_REG_EVENT (&cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
	if (VMI_SUCCESS != vmi_register_event (xa.vmi, &cr3_event)) {
		clog_error (CLOG(CLOGGER_ID), "Failed to setup cr3 event");
		goto exit;
	}
#endif

#endif

	clog_info (CLOG(CLOGGER_ID), "Entering VMI event loop");
	vmi_resume_vm (xa.vmi);

	while (!interrupted) {
		status_t status = vmi_events_listen (xa.vmi, 500);
		if (status != VMI_SUCCESS) {
			clog_error (CLOG(CLOGGER_ID), "Some issue in the event_listen loop. Aborting!");
			interrupted = true;
			rc = EBUSY;
		}
	}

	vmi_pause_vm (xa.vmi);

exit:
	clog_info (CLOG(CLOGGER_ID), "Exited VMI event loop");

	xa.loop_status = rc;
	*xa.ext_nif_busy = false;
	sem_post (&xa.loop_complete);

	return NULL;
}


void
nif_fini(void)
{
	clog_info (CLOG(CLOGGER_ID), "Waiting for Xen event loop to shut down...");
	if (event_loop_thread)
	{
		g_thread_join (event_loop_thread);
		event_loop_thread = NULL;
	}
	clog_info (CLOG(CLOGGER_ID), "Xen event loop has shut down...");

	// The VM was paused when the loop exited

	fflush (stdout);

	if (NULL != xa.shadow_pnode_mappings) {
		g_hash_table_destroy (xa.shadow_pnode_mappings);
	}
	if (NULL != xa.pframe_sframe_mappings) {
		g_hash_table_destroy (xa.pframe_sframe_mappings);
	}

	destroy_views(xa.domain_id);

	fini_xen_monitor();

	vmi_resume_vm(xa.vmi);

	vmi_destroy(xa.vmi);

	sem_destroy (&xa.start_loop);
	sem_destroy (&xa.loop_complete);
}


int
nif_init(const char* name,
	 bool * nif_busy)
{
	vmi_event_t trap_event, mem_event, cr3_event;
	status_t status;
	int rc = 0;

	// Not in event loop yet...
	xa.ext_nif_busy = nif_busy;

	*xa.ext_nif_busy = true;

	// Initialize the libvmi library.
	if (VMI_FAILURE ==
	    vmi_init_complete(&xa.vmi, (void*)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS,NULL,
			      VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to init LibVMI library.\n");
		goto exit;
	}

	rc = init_xen_monitor(name);
	if (rc) {
		goto exit;
	}

	xa.pframe_sframe_mappings = g_hash_table_new (NULL, NULL);
	xa.shadow_pnode_mappings = g_hash_table_new_full (NULL, NULL, NULL, free_nif_page_node);

	// Pause the VM here. It is resumed via nif_event_loop() and nif_fini()
	vmi_pause_vm(xa.vmi);

	if (0 != xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 1)) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to enable altp2m for domain_id: %u\n", xa.domain_id);
		goto exit;
	}

	if (0 != xc_altp2m_create_view(xa.xci, xa.domain_id, 0, &alt_view1)) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to create execute view\n");
		goto exit;
	}


	if (0 != xc_altp2m_switch_to_view(xa.xci, xa.domain_id, alt_view1)) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to switch to execute view id:%u\n", alt_view1);
		goto exit;
	}

	clog_info (CLOG(CLOGGER_ID), "Altp2m: alt_view1 created and activated");

	status = vmi_pid_to_dtb (xa.vmi, 0, &xa.kdtb);
	if (VMI_FAILURE == status) {
		rc = EIO;
		clog_error (CLOG(CLOGGER_ID), "Failed to find kernel page table base");
		goto exit;
	}

	rc = sem_init (&xa.start_loop, 0, 0);
	if (rc) {
		clog_error (CLOG(CLOGGER_ID), "sem_init() failed: %d", rc);
		goto exit;
	}

	rc = sem_init (&xa.loop_complete, 0, 0);
	if (rc) {
		clog_error (CLOG(CLOGGER_ID), "sem_init() failed: %d", rc);
		goto exit;
	}

	event_loop_thread = g_thread_new ("vmi_event_looper", nif_event_loop_worker, NULL);

exit:
	return rc;
}


int
nif_get_vmi (vmi_instance_t * vmi)
{
	*vmi = xa.vmi;
	return 0;
}

void
nif_stop (void)
{
	// Called via signal handler; don't block
	interrupted = true;

	// Kick off event loop in case it hasn't started yet
	sem_post (&xa.start_loop);

	clog_warn (CLOG(CLOGGER_ID), "Received request to shutdown VMI event loop");
}


int
nif_event_loop (void)
{
	int rc = 0;

	// Release the thread to start looping
	sem_post (&xa.start_loop);

	// Wait for exit

	sem_wait (&xa.loop_complete);
	return xa.loop_status;
}

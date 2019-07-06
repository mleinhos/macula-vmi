/**
 * Description: Abstraction layer above libvmi and single-step
 *              techniques for ARM and x86. Allows user to register
 *              callbacks on either first or second event.
 *
 * Company: Numen Inc.
 *
 * Developers: Ali Islam
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
#define ALTP2M_DEFAULT_VIEW (p2m_view_t)(0)

#define ALTP2M_DEFAULT_GFN ~(0UL)


#if defined(ARM64)

typedef uint32_t trap_val_t;

#define TRAP_CODE 0xd4000003

#else

static vmi_event_t ss_event[MAX_VCPUS];
typedef uint8_t trap_val_t;

#define TRAP_CODE 0xcc

#endif

static int act_calls = 0;
static GThread * event_loop_thread = NULL;

struct _nif_hook_node;

// Track global state
typedef struct
{
	libxl_ctx* xcx;
	xc_interface* xci;
	uint32_t domain_id;
	vmi_instance_t vmi;

//	nvmi_level_t curr_level;
	nvmi_level_t requested_level;

	// View where just a few pivital points are instrumented. For
	// now it is the default view. FIXME:
	p2m_view_t trigger_view;

	// View where all activated syscalls and instr points are trapped
	p2m_view_t active_view;

	// View where instructions after every possibly-instrumented
	// syscall and instr points are trapped. TODO: SS view needs
	// to include SMC at __schedule, so context switches are
	// caught and NInspector always stays in sync with the process
	// context. Failure to do this could result in two SS SMCs
	// being hit in a row, which we won't recover from.
	p2m_view_t   ss_view;

	addr_t kdtb;

	uint64_t orig_mem_size;
	xen_pfn_t max_gpfn;

	// Track the most recent hook node for each vCPU
        struct _nif_hook_node* vcpu_hook_nodes[MAX_VCPUS];

	GHashTable* pframe_sframe_mappings; //key:pframe

	GHashTable* shadow_pnode_mappings; //key:shadow

	// Fast lookup for BP
	GHashTable* gpa_hook_mappings; // GPA -> hook_node

	volatile bool interrupted;
	sem_t start_loop;
	sem_t loop_complete;
	bool * ext_nif_busy;
	int loop_status;

} nif_xen_monitor;

// Track one page containing instrumentation point
typedef struct _nif_page_node
{
	addr_t		orig_frame;
	addr_t		shadow_frame;
	addr_t		shadow_frame_ss;
	GHashTable* 	offset_bp_mappings; // key:offset
} nif_page_node;

// Track one hook (instrumentation point)
//
// TODO: A hook on ARM has two parts: (1) The entry, and (2) The exit,
// which are split across two actual hooks (SMCs) in the guest
// memory. Once (1) has executed, it is imperative that (2) executes
// as well before (a) a context switch or (b) the hook is
// disabled. The code has to guard against those two possibilities.
//
// To guard against (a), an additional instrumentation point at
// schedule() or __schedule() should be set in the same view as the
// second SMC. It may also be possible to address (a) via a per-VCPU
// lock. For (b), each hook should be guarded by a lock (ideally a RW
// lock or spinlock) such that the lock is acquired upon the entry of
// (1) and released upon the exit of (2); that lock must be acquired
// (write lock if RW lock is used) before the hook can be
// disabled. Note that glib supports a RW lock, and pthread has a
// spinlock implementation.
typedef struct _nif_hook_node
{
	addr_t			offset;
	char 			name[SYSCALL_MAX_NAME_LEN];
	nif_page_node*		parent;

	// Callbacks registered by layer above us
	nif_event_callback_t	pre_cb;
	nif_event_callback_t	post_cb;
	void* 			cb_arg;

	bool                    trigger;

	// Synchronization of callback:
	//
	// (1) The system cannot be torn down while a callback is
	//     executing (since it might use libvmi), and
	//
	// (2) A callback cannot be deactivated while the callback is
	//    executing, but
	//
	// (3) A callback can be executing on multiple vCPUs at once.
	//
	// Thus, a read lock must first be acquired before a callback
	// can execute. A write lock must be acquired to deactivate a
	// hook point and/or to tear down the system.
	GRWLock               lock;
	bool                  rlocked;
	bool                  wlocked;
	 // orig value in shadow frame (init instr point)
	trap_val_t             backup_val1;
#if defined(ARM64)
	// orig value in orig view (secondary instr point)
	trap_val_t             backup_val2;
#endif
} nif_hook_node;

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
				     MKADDR(hook_node->parent->orig_frame, hook_node->offset) + 4,
				     hook_node->backup_val2);
#endif
	if (VMI_SUCCESS != status)
	{
		nvmi_error ("Failed to restore original hookpoint values near PA=%" PRIx64 "",
			    MKADDR(hook_node->parent->shadow_frame, hook_node->offset));
	}

	g_free(hook_node);
}


/**
 * Compute the next view, based on the current state.
 */
static inline p2m_view_t
get_requested_view (bool in_ss)
{
	// A reasonable way to fail...
	p2m_view_t nextv = xa.trigger_view;

	if (in_ss)
	{
		// Secondary (singlestep) breakpoint: go to requested view
		if (xa.interrupted)
		{
			nextv = ALTP2M_DEFAULT_VIEW;
			goto exit;
		}
		switch (xa.requested_level)
		{
		case NVMI_MONITOR_LEVEL_TRIGGERS:
			nextv = xa.trigger_view;
			break;
		case NVMI_MONITOR_LEVEL_ACTIVE:
			nextv = xa.active_view;
			break;
		default:
			nvmi_error ("How to handle current state?");
		}
	}
	else
	{
		// Initial breakpoint: ARM goes to SS view, Intel to default
#if defined(ARM64)
		nextv = xa.ss_view;
#else
		nextv = ALTP2M_DEFAULT_VIEW;
#endif
	}
exit:
	return nextv;
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
	addr_t gpa = 0;

	// If applicable, handle event from single step view.
	if (event->slat_id == xa.ss_view)
	{
		// Go back to "normal" view
		event->slat_id = get_requested_view (true);

		// Grab the hook node used to get us here to the
		// secondary (SS) view. The rlock may have failed
		// earlier; if so, don't invoke CB.
		hook_node = xa.vcpu_hook_nodes [event->vcpu_id];
		assert (NULL != hook_node);

		if (NULL != hook_node)
		{
			if (hook_node->post_cb && hook_node->rlocked)
			{
				hook_node->post_cb (vmi, NULL, hook_node->cb_arg);
			}
		}

		if (hook_node->rlocked)
		{
			g_rw_lock_reader_unlock (&hook_node->lock);
			hook_node->rlocked = false;
		}

		return (VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
	}

	// Otherwise this is the initial hook. Lookup the guest physical addr.
	gpa = MKADDR(event->privcall_event.gfn, event->privcall_event.offset);
	hook_node = g_hash_table_lookup (xa.gpa_hook_mappings, GSIZE_TO_POINTER(gpa));

	xa.vcpu_hook_nodes [event->vcpu_id] = hook_node;
	if (NULL == hook_node)
	{
		nvmi_error ("No BP record found for this GPA %" PRIx64 ".", gpa);
		return VMI_EVENT_RESPONSE_NONE;
	}

	// We expect to move to SS view here, regardless of request or
	// further results. Must switch to a view where this SMC does
	// not exist (avoid loop)
	event->slat_id = get_requested_view (false);

	// We found the hook node. Lock it or bail out. Even if locking fails, the SS view is still used!
	hook_node->rlocked = g_rw_lock_reader_trylock (&hook_node->lock);
	if (!hook_node->rlocked)
	{
		nvmi_error ("Failed to acquire lock for hook \"%s\". Blocking callback.",
			    hook_node->name);
		goto exit;
	}

	// Since the trigger and active views share frames, sometimes
	// we'll incur a notification in trigger view for a
	// non-trigger CB. In that case, don't notify the user.
	if (event->slat_id == xa.trigger_view && !hook_node->trigger)
	{
		nvmi_debug ("Ignoring non-trigger hook in trigger view: %s", hook_node->name);
	}
	else if (hook_node->pre_cb)
	{
		hook_node->pre_cb (vmi, event, hook_node->cb_arg);
	}

exit:
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
	addr_t gpa = 0;

	// Lookup the guest physical addr.
	gpa = MKADDR(event->interrupt_event.gfn, event->interrupt_event.offset);
	hook_node = g_hash_table_lookup (xa.gpa_hook_mappings, GSIZE_TO_POINTER(gpa));

	xa.vcpu_hook_nodes [event->vcpu_id] = hook_node;
	if (NULL == hook_node)
	{
		nvmi_error ("No BP record found for this GPA %" PRIx64 ".", gpa);
		event->interrupt_event.reinject = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	// We found the hook node. Lock it or bail out. First store it for SS callback.
	hook_node->rlocked = g_rw_lock_reader_trylock (&hook_node->lock);
	if (!hook_node->rlocked)
	{
		nvmi_error ("Warning: Failed to acquire hook lock %s. Blocking callback.",
			    hook_node->name);
		goto exit;
	}

	// Since the trigger and active views share frames, sometimes
	// we'll incur a notification in trigger view for a
	// non-trigger CB. In that case, don't notify the user.
	if (event->slat_id == xa.trigger_view && !hook_node->trigger)
	{
		nvmi_debug ("Ignoring non-trigger hook in trigger view: %s", hook_node->name);
	}
	else if (hook_node->pre_cb)
	{
		hook_node->pre_cb (vmi, event, hook_node->cb_arg);
	}

exit:
	event->interrupt_event.reinject = 0;
	// Must switch to a view where this BP does not exist (avoid loop)
	event->slat_id = get_requested_view (false);
	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP|
		VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}
#endif // ARM64


static void
free_nif_page_node (gpointer data)
{
	nif_page_node* pnode = data;

	nvmi_debug ("Disabling monitoring of mfn=%" PRIx64 ", shadow=%" PRIx64,
		    pnode->orig_frame, pnode->shadow_frame);

	if (NULL != pnode->offset_bp_mappings)
	{
		GList * hooks = g_hash_table_get_values (pnode->offset_bp_mappings);
		GList * ihook = NULL;

		for (ihook = hooks; ihook != NULL; ihook = ihook->next)
		{
			nif_hook_node * node = (nif_hook_node *) ihook->data;
			addr_t gpa = MKADDR (pnode->orig_frame, node->offset);

			if (g_hash_table_contains (xa.gpa_hook_mappings, GSIZE_TO_POINTER(gpa)))
			{
				//nvmi_debug ("gpa->hook mapping: removing %s", node->name);
				g_hash_table_remove (xa.gpa_hook_mappings, GSIZE_TO_POINTER(gpa));
			}
			else
			{
				nvmi_warn ("gpa->hook mapping doesn't contain GPA %" PRIX64,
					   GSIZE_TO_POINTER(gpa));
			}
		}
		g_list_free (hooks);

		g_hash_table_destroy(pnode->offset_bp_mappings);
	}

	// Stop monitoring
	vmi_set_mem_event(xa.vmi,
			  pnode->shadow_frame,
			  VMI_MEMACCESS_N,
			  xa.active_view);

	xc_altp2m_change_gfn (xa.xci, xa.domain_id, xa.active_view, pnode->shadow_frame, ALTP2M_DEFAULT_GFN);
	xc_domain_decrease_reservation_exact (xa.xci,
					      xa.domain_id,
					      1, 0,
					      (xen_pfn_t*)&pnode->shadow_frame);

#if defined(ARM64)
	xc_altp2m_change_gfn (xa.xci, xa.domain_id, xa.active_view, pnode->shadow_frame_ss, ALTP2M_DEFAULT_GFN);
	xc_domain_decrease_reservation_exact (xa.xci,
					      xa.domain_id,
					      1, 0,
					      (xen_pfn_t*)&pnode->shadow_frame_ss);
#endif

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
	if (VMI_SUCCESS != status)
	{
		rc = EINVAL;
		nvmi_error ("Failed to find PA for kernel VA=%" PRIx64 "", kva);
		goto exit;
	}

	hook_node = g_hash_table_lookup (xa.gpa_hook_mappings, GSIZE_TO_POINTER(pa));

	*monitored = (NULL != hook_node);

exit:
	return rc;
}


// TODO: refactor this -- it's too big
int
nif_enable_monitor (addr_t kva,
		    const char* name,
		    nif_event_callback_t pre_cb,
		    nif_event_callback_t post_cb,
		    void* cb_arg,
		    bool is_trigger)
{
	int rc = 0;
	size_t ret;
	status_t status;
	nif_page_node * pgnode  = NULL;
	nif_hook_node * hook_node = NULL;
	addr_t pa, orig_frame, offset;
	addr_t shadow_frame = 0, shadow_frame_ss = 0;
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
	if (VMI_SUCCESS != status)
	{
		rc = EACCES;
		nvmi_error ("Failed to read orig val near %" PRIx64 "", kva);
		goto exit;
	}

	status = vmi_pagetable_lookup (xa.vmi, xa.kdtb, kva, &pa);
	if (VMI_SUCCESS != status)
	{
		rc = EINVAL;
		nvmi_error ("Failed to find PA for kernel VA=%" PRIx64 "", kva);
		goto exit;
	}

	orig_frame = pa >> PG_OFFSET_BITS;
	offset = pa % DOM_PAGE_SIZE;

	shadow_frame = (addr_t) GPOINTER_TO_SIZE (g_hash_table_lookup(xa.pframe_sframe_mappings,
								      GSIZE_TO_POINTER(orig_frame)));
	if (0 == shadow_frame)
	{
		// Allocate frame if not already there
		shadow_frame = ++(xa.max_gpfn);
		rc = xc_domain_populate_physmap_exact (xa.xci, xa.domain_id, 1, 0, 0, (xen_pfn_t*)&shadow_frame);
		if (rc < 0)
		{
			rc = ENOMEM;
			nvmi_error ("Failed to allocate frame at %" PRIx64 "", shadow_frame);
			goto exit;
		}

		// Update p2m mapping: active_view: frame --> shadow_frame
		rc = xc_altp2m_change_gfn (xa.xci, xa.domain_id, xa.active_view, orig_frame, shadow_frame);
		if (rc)
		{
			rc = EACCES;
			nvmi_error ("Shadow: Unable to change mapping for active_view");
			goto exit;
		}

#if defined(ARM64)
		shadow_frame_ss = ++(xa.max_gpfn);
		rc = xc_domain_populate_physmap_exact (xa.xci, xa.domain_id, 1, 0, 0, (xen_pfn_t*)&shadow_frame_ss);
		if (rc < 0)
		{
			rc = ENOMEM;
			nvmi_error ("Failed to allocate frame at %" PRIx64 "", shadow_frame_ss);
			goto exit;
		}

		rc = xc_altp2m_change_gfn (xa.xci, xa.domain_id, xa.ss_view, orig_frame, shadow_frame_ss);
		if (rc)
		{
			rc = EACCES;
			nvmi_error ("Shadow: Unable to change mapping for active_view");
			goto exit;
		}
#endif
		// Record the new translation
		g_hash_table_insert (xa.pframe_sframe_mappings,
				     GSIZE_TO_POINTER(orig_frame), GSIZE_TO_POINTER(shadow_frame));
	}
	else
	{
		shadow_frame_ss	= shadow_frame + 1; // Used only on ARM
	}

	// shadow_frame is now known
	nvmi_debug ("shadow_frame %lx for va %lx", shadow_frame, kva);

	pgnode = g_hash_table_lookup (xa.shadow_pnode_mappings, GSIZE_TO_POINTER(shadow_frame));
	if (NULL == pgnode)
	{
		// Copy orig frame into shadow
		status = vmi_read_pa (xa.vmi, MKADDR(orig_frame, 0), DOM_PAGE_SIZE, buff, &ret);
		if (DOM_PAGE_SIZE != ret || status == VMI_FAILURE)
		{
			rc = EACCES;
			nvmi_error ("Shadow: Failed to read target page, frame=%lx", orig_frame);
			goto exit;
		}

		status = vmi_write_pa (xa.vmi, MKADDR(shadow_frame, 0), DOM_PAGE_SIZE, buff, &ret);
		if (DOM_PAGE_SIZE != ret || status == VMI_FAILURE)
		{
			rc = EACCES;
			nvmi_error ("Shadow: Failed to write to shadow page");
			goto exit;
		}

#if defined(ARM64)
		// Copy orig into shadow SS
		status = vmi_write_pa (xa.vmi, MKADDR(shadow_frame_ss, 0), DOM_PAGE_SIZE, buff, &ret);
		if (DOM_PAGE_SIZE != ret || status == VMI_FAILURE)
		{
			rc = EACCES;
			nvmi_error ("Shadow: Failed to write to shadow SS page");
			goto exit;
		}
#endif
		// Update the hks list
		pgnode                  = g_new0(nif_page_node, 1);
		pgnode->shadow_frame    = shadow_frame;
		pgnode->shadow_frame_ss = shadow_frame_ss; // Intel: this is ignored
		pgnode->orig_frame      = orig_frame;
		pgnode->offset_bp_mappings = g_hash_table_new_full (NULL, NULL, NULL, free_pg_hks_lst);

		g_hash_table_insert (xa.shadow_pnode_mappings,
				     GSIZE_TO_POINTER(shadow_frame),
				     pgnode);
	}
	else
	{
		// Check for existing hooks: if one exists, we're done
		hook_node = g_hash_table_lookup (pgnode->offset_bp_mappings,
						 GSIZE_TO_POINTER(offset));
		if (NULL != hook_node)
		{
			nvmi_error ("Found hook already in place for va %" PRIx64 "", kva);
			goto exit;
		}
	}

	// TODO: experiment with the second callback: can we change it
	// to be notified on an access to schedule() / __schedule()
	// rather than the very next instruction? This applies to
	// Intel too -- is a second #BP faster than single stepping?

	// Write the trap/smc value(s): The first goes in the shadow
	// page, the second (ARM only) goes in the SS page.
	nvmi_debug ("Writing trap %x to PA %" PRIx64 ", backup1=%x",
		    TRAP_CODE, MKADDR(shadow_frame, offset), orig1);
	status  = write_trap_val_pa (xa.vmi, MKADDR(shadow_frame, offset), TRAP_CODE);
#if defined(ARM64)
	nvmi_debug ("ARM: Writing SS trap %x to PA %" PRIx64 ", backup2=%x",
		    TRAP_CODE, MKADDR(shadow_frame_ss, offset) + 4, orig2);
	status |= write_trap_val_pa (xa.vmi, MKADDR(shadow_frame_ss, offset) + 4, TRAP_CODE);
#endif
	if (VMI_SUCCESS != status)
	{
		rc = EACCES;
		nvmi_error ("Failed to write trap val in a shadow page");
		goto exit;
	}

	// In case of a triggering instr point, write it to the
	// default view (for now). Note the TRAP_CODE was already
	// written into shadow_frame.  FIXME:
	if (is_trigger)
	{
		nvmi_info ("Writing trap %s into trigger view", name);

		// Update p2m mapping: trigger_view: frame --> shadow_frame
		rc = xc_altp2m_change_gfn (xa.xci, xa.domain_id, xa.trigger_view, orig_frame, shadow_frame);
		if (rc)
		{
			rc = EACCES;
			nvmi_error ("Shadow: Unable to change mapping for trigger_view");
			goto exit;
		}
	}

	// Create new hook node and save it
	hook_node = g_new0(nif_hook_node, 1);
	strncpy (hook_node->name, name, SYSCALL_MAX_NAME_LEN);
	hook_node->parent     = pgnode;
	hook_node->offset     = offset;
	hook_node->pre_cb     = pre_cb;
	hook_node->post_cb    = post_cb;
	hook_node->cb_arg     = cb_arg;
	hook_node->trigger    = is_trigger;
	hook_node->backup_val1 = orig1;
#if defined(ARM64)
	hook_node->backup_val2 = orig2;
#endif

	g_hash_table_insert(pgnode->offset_bp_mappings, GSIZE_TO_POINTER(offset), hook_node);
	g_hash_table_insert(xa.gpa_hook_mappings, GSIZE_TO_POINTER(pa), hook_node);

exit:
	return rc;
}


int
nif_disable_monitor (addr_t kva)
{
	int rc = ENOTSUP;

exit:
	return rc;
}


int
nif_set_level (nvmi_level_t level)
{
	int rc = 0;
	const char * lname = "<Unknown>";


	switch (level)
	{
	case   NVMI_MONITOR_LEVEL_TRIGGERS:
		lname = "TRIGGER";
		break;
	case   NVMI_MONITOR_LEVEL_ACTIVE:
		lname = "ACTIVE";
		break;
	case   NVMI_MONITOR_LEVEL_PARANOID:
		lname = "PARANOID";
		break;

	case	NVMI_MONITOR_LEVEL_UNSET:
	default:
		nvmi_info ("Unexpected monitoring level requested: %d", level);
		rc = EINVAL;
		goto exit;
	}

	xa.requested_level = level;

exit:
	nvmi_info ("Requested monitoring level: %s", lname);

	return rc;
}




#if !defined(ARM64)

static event_response_t
singlestep_cb(vmi_instance_t vmi, vmi_event_t* event)
{

	nif_hook_node* hook_node = xa.vcpu_hook_nodes [event->vcpu_id];

	assert (NULL != hook_node); // && true == hook_node->locked);
	if (NULL != hook_node)
	{
		if (hook_node->post_cb)
		{
			hook_node->post_cb (vmi, NULL, hook_node->cb_arg);
		}
	}

	if (hook_node->rlocked)
	{
		g_rw_lock_reader_unlock (&hook_node->lock);
		hook_node->rlocked = false;
	}
	else
	{
		nvmi_warn ("Found hook %s unlocked; not attempting unlock", hook_node->name);
	}
	event->slat_id = get_requested_view (true);

	return (VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP |
		VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID);
}

static int
setup_ss_events (vmi_instance_t vmi)
{
	int vcpus = vmi_get_num_vcpus(vmi);
	int rc = 0;

	nvmi_info ("Domain vcpus=%d", vcpus);

	if (0 == vcpus)
	{
		rc = EIO;
		nvmi_error ("Failed to find the total VCPUs");
		goto exit;
	}

	if (vcpus > MAX_VCPUS)
	{
		rc = EINVAL;
		nvmi_error ("Guest VCPUS are greater than what we can support");
			goto exit;
	}

	for (int i = 0; i < vcpus; i++)
	{
		SETUP_SINGLESTEP_EVENT (&ss_event[i], 1u << i, singlestep_cb, 0);

		if (VMI_SUCCESS != vmi_register_event(vmi, &ss_event[i])) {
			rc = EIO;
			nvmi_error ("Failed to register SS event on VCPU %d: %d", i, rc);
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
	nvmi_info ("Integrity check served");

	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	       | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}
#endif


static void
fini_xen_monitor(void)
{
	if (xa.xcx)
	{
		if (0 != libxl_ctx_free(xa.xcx))
		{
			nvmi_error ("Failed to close xl handle");
		}
		xa.xcx = NULL;
	}

	if (xa.xci)
	{
		if (0 != xc_interface_close(xa.xci))
		{
			nvmi_error ("Failed to close connection to xen interface");
		}
		xa.xci = NULL;
	}
}


static void
destroy_views (void)
{
	if (NULL == xa.xci)
	{
		return;
	}

	if (0 != xc_altp2m_switch_to_view(xa.xci, xa.domain_id, ALTP2M_DEFAULT_VIEW))
	{
		nvmi_error ("Failed to switch to default view");
	}

	if (xa.active_view)
	{
		xc_altp2m_destroy_view(xa.xci, xa.domain_id, xa.active_view);
		xa.active_view = 0;
	}

	if (xa.trigger_view)
	{
		xc_altp2m_destroy_view(xa.xci, xa.domain_id, xa.trigger_view);
		xa.trigger_view = 0;
	}

	if (xa.ss_view)
	{
		xc_altp2m_destroy_view (xa.xci, xa.domain_id, xa.ss_view);
		xa.ss_view = 0;
	}

	if (0 != xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 0))
	{
		nvmi_error ("Failed to disable altp2m for domain_id: %u", xa.domain_id);
	}
}


#define MAX_LOCK_BREAK_ATTEMPTS 3

static void
break_hook_lock (nif_hook_node * node)
{
	int tries = 0;
	while (tries++ < MAX_LOCK_BREAK_ATTEMPTS)
	{
		node->wlocked = g_rw_lock_writer_trylock (&node->lock);
		if (node->wlocked)
		{
			break;
		}
		nvmi_warn ("Can't lock node %s, waiting...", node->name);
		usleep(20);
	}

	if (!node->wlocked)
	{
		nvmi_warn ("Breaking lock on node %s, waiting...", node->name);
		g_rw_lock_reader_unlock (&node->lock);
		node->rlocked = false;
		if (!g_rw_lock_writer_trylock (&node->lock))
		{
			nvmi_error ("Still can't acquire lock on node %s", node->name);
		}
	}
}


static void
allow_callbacks (bool allowed)
{
	GList * pages = NULL;
	GList * ipage = NULL;

	pages = g_hash_table_get_values (xa.shadow_pnode_mappings);

	for (ipage = pages; ipage != NULL; ipage = ipage->next)
	{
		GList * hooks = NULL;
		GList * ihook = NULL;
		nif_page_node * pgnode = ipage->data;
		hooks = g_hash_table_get_values ((GHashTable *) pgnode->offset_bp_mappings);

		for (ihook = hooks; ihook != NULL; ihook = ihook->next)
		{
			nif_hook_node * node = (nif_hook_node *) ihook->data;
			nvmi_debug ("%sing node %s",
				    (allowed ? "Unlock" : "Lock"),
				    node->name);
			if (allowed)
			{
				if (node->wlocked)
				{
					g_rw_lock_writer_unlock (&node->lock);
					node->wlocked = false;
				}
			}
			else
			{
				node->wlocked = g_rw_lock_writer_trylock (&node->lock);
				if (!node->wlocked)
				{
					break_hook_lock (node);
				}
			}
		} // inner for
		g_list_free (hooks);
	} // outer
	g_list_free (pages);
}


static int
init_xen_monitor(const char* name)
{
	int rc = 0;
	if (0 == (xa.xci = xc_interface_open(NULL, NULL, 0)))
	{
		nvmi_error ("Failed to open xen interface");
		return EIO; // nothing to clean
	}

	if (libxl_ctx_alloc(&xa.xcx, LIBXL_VERSION, 0, NULL))
	{
		rc = ENOMEM;
		nvmi_error ("Unable to create xl context");
		goto clean;
	}

	if ( libxl_name_to_domid(xa.xcx, name, &xa.domain_id))
	{
		rc = EINVAL;
		nvmi_error ("Unable to get domain id for %s", name);
		goto clean;
	}

	if (0 == (xa.orig_mem_size = vmi_get_memsize(xa.vmi)))
	{
		rc = EIO;
		nvmi_error ("Failed to get domain memory size");
		goto clean;
	}

	if (xc_domain_maximum_gpfn(xa.xci, xa.domain_id, &xa.max_gpfn) < 0)
	{
		rc = EIO;
		nvmi_error ("Failed to get max gpfn for the domain");
		goto clean;
	}

	//nvmi_info ("Max gfn:%" PRIx64 "",xa.max_gpfn);
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

	if (xa.interrupted)
	{
		goto exit;
	}

	nvmi_info ("Starting VMI event loop");

#if defined(ARM64)
	SETUP_PRIVCALL_EVENT(&main_event, _internal_hook_cb);
	main_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event(xa.vmi, &main_event)) {
		nvmi_error ("Unable to register privcall event");
		goto exit;
	}
#else
	rc = setup_ss_events(xa.vmi);
	if (rc)
	{
		goto exit;
	}

#if VMI_EVENTS_VERSION >= 0x6
	SETUP_INTERRUPT_EVENT (&main_event, _internal_hook_cb);
#else
	SETUP_INTERRUPT_EVENT (&main_event, 0, _internal_hook_cb);
#endif

	main_event.data = &xa;
	if (VMI_SUCCESS != vmi_register_event (xa.vmi, &main_event))
	{
		nvmi_error ("Unable to register interrupt event");
		goto exit;
	}

#if 0
	// Not necessary: If we don't trust the user address space
	// cache on a callback, we should invalidate it in the
	// callback and not add another callback!
	SETUP_REG_EVENT (&cr3_event, CR3, VMI_REGACCESS_W, 0, cr3_cb);
	if (VMI_SUCCESS != vmi_register_event (xa.vmi, &cr3_event))
	{
		nvmi_error ("Failed to setup cr3 event");
		goto exit;
	}
#endif

#endif

	nvmi_info ("Entering VMI event loop: resuming VM");
	vmi_resume_vm (xa.vmi);

	while (!xa.interrupted)
	{
		status_t status = vmi_events_listen (xa.vmi, 500);
		if (status != VMI_SUCCESS)
		{
			nvmi_error ("Some issue in the event_listen loop. Aborting!");
			xa.interrupted = true;
			rc = EBUSY;
		}
	}

	// Flush out events (which require read lock) before locking down callbacks with write lock
	nvmi_info ("Flushing out final events...");
	(void) vmi_events_listen (xa.vmi, 1000);
	nvmi_info ("...done. All events should be completed.");
	allow_callbacks (false);

	vmi_pause_vm (xa.vmi);

exit:
	nvmi_info ("Exited VMI event loop");

	xa.loop_status = rc;
	*xa.ext_nif_busy = false;
	sem_post (&xa.loop_complete);

	return NULL;
}


void
nif_fini(void)
{
	nvmi_info ("Waiting for Xen event loop to shut down...");
	if (event_loop_thread)
	{
		g_thread_join (event_loop_thread);
		event_loop_thread = NULL;
	}
	nvmi_info ("Xen event loop has shut down...");

	// The VM was paused when the loop exited

	fflush (stdout);

	if (NULL != xa.shadow_pnode_mappings)
	{
		g_hash_table_destroy (xa.shadow_pnode_mappings);
		xa.shadow_pnode_mappings = NULL;
	}
	if (NULL != xa.pframe_sframe_mappings)
	{
		g_hash_table_destroy (xa.pframe_sframe_mappings);
		xa.pframe_sframe_mappings = NULL;
	}

	if (NULL != xa.gpa_hook_mappings)
	{
		g_hash_table_destroy (xa.gpa_hook_mappings);
		xa.gpa_hook_mappings = NULL;
	}

	destroy_views();

	fini_xen_monitor();

	nvmi_info ("Resuming VM");
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
	    vmi_init_complete(&xa.vmi, (void*)name, VMI_INIT_DOMAINNAME| VMI_INIT_EVENTS,
			      NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL))
	{
		rc = EIO;
		nvmi_error ("Failed to init LibVMI library.");
		goto exit;
	}

	rc = init_xen_monitor(name);
	if (rc)
	{
		goto exit;
	}

	xa.pframe_sframe_mappings = g_hash_table_new (NULL, NULL);
	xa.shadow_pnode_mappings = g_hash_table_new_full (NULL, NULL, NULL, free_nif_page_node);
	xa.gpa_hook_mappings  = g_hash_table_new (NULL, NULL);

	// Pause the VM here. It is resumed via nif_event_loop() and nif_fini()
	vmi_pause_vm(xa.vmi);

	if (0 != xc_altp2m_set_domain_state(xa.xci, xa.domain_id, 1))
	{
		rc = EIO;
		nvmi_error ("Failed to enable altp2m for domain_id: %u", xa.domain_id);
		goto exit;
	}

	if (0 != xc_altp2m_create_view (xa.xci, xa.domain_id, 0, &xa.trigger_view))
	{
		rc = EIO;
		nvmi_error ("Failed to create trigger view");
		goto exit;
	}

//	nvmi_warn ("Fixing trigger view to default view");
//	xa.trigger_view = ALTP2M_DEFAULT_VIEW;

	if (0 != xc_altp2m_create_view (xa.xci, xa.domain_id, 0, &xa.active_view))
	{
		rc = EIO;
		nvmi_error ("Failed to create active view");
		goto exit;
	}

#if defined(ARM64)
	if (0 != xc_altp2m_create_view (xa.xci, xa.domain_id, 0, &xa.ss_view))
	{
		rc = EIO;
		nvmi_error ("Failed to create SS view");
		goto exit;
	}
#endif
	// Policy: start the monitoring off in trigger view
	if (0 != xc_altp2m_switch_to_view (xa.xci, xa.domain_id, xa.trigger_view))
	{
		rc = EIO;
		nvmi_error ("Failed to switch to active view id:%u", xa.active_view);
		goto exit;
	}
	xa.requested_level = NVMI_MONITOR_LEVEL_TRIGGERS;

	nvmi_info ("Altp2m: active_view created and activated");

	status = vmi_pid_to_dtb (xa.vmi, 0, &xa.kdtb);
	if (VMI_FAILURE == status)
	{
		rc = EIO;
		nvmi_error ("Failed to find kernel page table base");
		goto exit;
	}

	rc = sem_init (&xa.start_loop, 0, 0);
	if (rc)
	{
		nvmi_error ("sem_init() failed: %d", rc);
		goto exit;
	}

	rc = sem_init (&xa.loop_complete, 0, 0);
	if (rc)
	{
		nvmi_error ("sem_init() failed: %d", rc);
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
	xa.interrupted = true;

	// Kick off event loop in case it hasn't started yet
	sem_post (&xa.start_loop);

	nvmi_warn ("Received request to shutdown VMI event loop");
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

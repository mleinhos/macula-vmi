/**
 * Description: Header file for the syscall monitoring on ARM and x86.
 *
 * Version: 3.0
 * 
 * Company: Numen Inc.
 *
 * Developer: Ali Islam
 */

#ifndef NVMI_H
#define NVMI_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <libxl.h>
#include <xenctrl.h>
#include <glib.h>

#define MAX_VCPUS 8
#define MAX_CALLS 400
#define MAX_SNAME_LEN 128
#define PG_OFFSET_BITS 12
#define DOM_PAGE_SIZE (1 << PG_OFFSET_BITS)

typedef void (*event_callback_t) (vmi_instance_t vmi, vmi_event_t *event);

typedef struct
{
	libxl_ctx *xcx;
	xc_interface *xci;
	uint32_t domain_id;
	vmi_instance_t vmi;

	uint64_t orig_mem_size;
	xen_pfn_t max_gpfn;

	GHashTable *pframe_sframe_mappings; //key:pframe

	GHashTable *shadow_pnode_mappings; //key:shadow

} nif_xen_monitor; //To avoid double pointers


typedef struct nif_page_node
{
	addr_t		frame;
	addr_t		shadow_frame;
	GHashTable 	*offset_bp_mappings; // key:offset
	nif_xen_monitor	*xa;
} nif_page_node;


typedef struct nif_hook_node
{
	addr_t			offset;
	char 			name[MAX_SNAME_LEN];
	nif_page_node		*parent;

	event_callback_t	cb1;

#if defined(ARM64)
	uint32_t 		backup_smc1; //on sframe
	uint32_t 		backup_smc2; //on frame
#else
	uint8_t 		backup_byte;
#endif
} nif_hook_node;



#endif // NVMI_H
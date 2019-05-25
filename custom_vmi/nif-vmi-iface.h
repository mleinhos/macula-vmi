/**
 * Description: Header file for the syscall monitoring on ARM and
 * x86. This defines the interface above the alternate memory views,
 * single stepping, etc. It facilitates a layer that focuses on
 * syscall monitoring only.
 *
 *
 * Version: 3.0
 *
 * Company: Numen Inc.
 *
 * Developer: Ali Islam
 */

#ifndef NIF_VMI_H
#define NIF_VMI_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <libxl.h>
#include <xenctrl.h>
#include <glib.h>

/**
 * Callback received by monitoring layer: it can observe the event but
 * cannot influence the response performed by the underlying layer.
 */
typedef void (*nif_event_callback_t) (vmi_instance_t vmi, vmi_event_t* event, void* arg);

/**
 * Functions return 0 on success, otherwise a positive errno.
 */

int
nif_init(const char* name,
	 bool * nif_busy);


void
nif_fini (void);


void
nif_stop(void);


int
nif_get_vmi (vmi_instance_t* vmi);


int
nif_event_loop (void);


int
nif_is_monitored(addr_t kva, bool * monitored);


int
nif_enable_monitor (addr_t kva,
                    const char* name,
                    nif_event_callback_t pre_cb,
                    nif_event_callback_t post_cb,
                    void* cb_arg);


int
nif_disable_monitor (addr_t kva);


#endif // NIF_VMI_H

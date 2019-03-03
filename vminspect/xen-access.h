#ifndef __XEN_ACCESS_H__
#define __XEN_ACCESS_H__

#include <libxl_utils.h>
#include <xenctrl.h>
#include <xenevtchn.h>

struct xen_control {
    uint32_t domain_id;
    xc_interface *xch;
    libxl_ctx* xlh;
    xenevtchn_handle *xce;
};

int init_xen_access(struct xen_control *xc, char *domain);
void cleanup_xen_access(struct xen_control *xc);

#endif /* __XEN_ACCESS_H__ */

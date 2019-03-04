#ifndef __VMINSPECT_H__
#define __VMINSPECT_H__

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
//#include <xenctrl.h>

#include "symbol.h"
#include "xen-access.h"

struct vminspect {
    char *profile;
    char *domain;
    vmi_arch_t arch;
    os_t os;
    unsigned int nr_syms;
    struct symbol *syms;
    unsigned int nr_syscalls;
    struct symbol *syscalls;

    struct xen_control xc;
    vmi_instance_t vmi;

    /* Xen altp2m */
    uint16_t altp2m_r_view;
    uint16_t altp2m_x_view;

    /* Events */
    vmi_event_t event_int3;
    vmi_event_t event_cr3;
    vmi_event_t event_mem;
};

#endif /* __VMINSPECT_H__ */

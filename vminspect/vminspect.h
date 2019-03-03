#ifndef __VMINSPECT_H__
#define __VMINSPECT_H__

#include <libvmi/libvmi.h>
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

    uint16_t altp2m_r_view;
    uint16_t altp2m_x_view;
};

#endif /* __VMINSPECT_H__ */

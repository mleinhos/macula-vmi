#ifndef __VMI_H__
#define __VMI_H__

#include <libvmi/libvmi.h>

#include "vminspect.h"

int init_vmi(struct vminspect *vminspect);
void cleanup_vmi(struct vminspect *vminspect);

#endif /* __VMI_H__ */

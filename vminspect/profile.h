#ifndef __PROFILE_H__
#define __PROFILE_H__

#include "vminspect.h"

#define REKALL_METADATA                     "$METADATA"
#define REKALL_METADATA_PROFILECLASS        "ProfileClass"
#define REKALL_METADATA_ARCH                "arch"

#define REKALL_CONSTANTS                    "$CONSTANTS"

int init_profile(struct vminspect *vminspect);
void cleanup_profile(struct vminspect *vminspect);

#endif /* __PROFILE_H__ */

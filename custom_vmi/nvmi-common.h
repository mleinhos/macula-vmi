/**
 * Description: Defines common stuff for all of the VMI portion of the NVMIsystem.
 *
 * Company: Numen Inc.
 *
 * Developers: Matt Leinhos
 */

#ifndef NVMI_COMMON_DEFS_H
#define NVMI_COMMON_DEFS_H


#define NVMI_MAX_SYSCALL_ARG_CT 6
#define NVMI_MAX_SYSCALL_CT 450


#ifndef NUMBER_OF
#   define NUMBER_OF(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef MIN
#    define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#    define MAX(x,y) ((x) < (y) ? (x) : (y))
#endif

#endif // NVMI_COMMON_DEFS_H

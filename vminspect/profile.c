#define _GNU_SOURCE         /* Needed by tsearch in search.h */
#include <json-c/json.h>
#include <search.h>
#include <string.h>

#include "profile.h"

static void profile_print_node(const void *p, const VISIT which, const int depth)
{
    struct symbol *syscall = *(struct symbol **) p;

    switch (which) {
    case postorder:
        /* Print binary tree nodes in order */
        printf("%lx : %s\n", syscall->address, syscall->name);
    case preorder:
    case endorder:
    case leaf:
        break;
    }
}

static int profile_compare_syscalls(const void *pa, const void *pb)
{
    struct symbol *syscall_a = (struct symbol *) pa;
    struct symbol *syscall_b = (struct symbol *) pb;

    if ( syscall_a->address < syscall_b->address )
        return -1;
    if ( syscall_a->address > syscall_b->address )
        return 1;

    return 0;
}

/*
 * Gather system calls and manage them in a binary tree to increase access
 * speed during lookup.
 */
static int profile_init_syscalls(struct vminspect *vminspect)
{
    int ret = -1;
    int i;

    vminspect->nr_syscalls = 0;

    for ( i=0; i<vminspect->nr_syms; i++ )
    {
        void *node;

        /* TODO: create a filter to filter out individual entries */

        /* We look for system calls only */
        if ( strncmp(vminspect->syms[i].name, "sys_", 4) )        
            continue;

        /* Skip the address of the system call table */
        if (!strcmp(vminspect->syms[i].name, "sys_call_table") )
            continue;

        node = tsearch((void *) &vminspect->syms[i], (void **) &vminspect->syscalls,
                       profile_compare_syscalls);

        if ( node == NULL )
        {
            printf("%s: Cannot add system call (symbol[%d] -- %lx : %s)\n",
                    __FUNCTION__, i, vminspect->syms[i].address,
                    vminspect->syms[i].name);
            goto err;
        }
        if ( *(struct symbol **)node != &vminspect->syms[i] )
        {
            printf("%s: WARNING: Skip ambiguous symbol[%d] -- %lx : %s\n",
                    __FUNCTION__, i, vminspect->syms[i].address,
                    vminspect->syms[i].name);
            //goto err;
        }

        vminspect->nr_syscalls++;
    }

    //twalk(vminspect->syscalls, profile_print_node);

    ret = 0;
err:
    return ret;
}

static int profile_init_syms(struct vminspect *vminspect)
{
    int ret = -1;
    int i = 0;
    json_object *json;
    json_object *json_syms;

    json = json_object_from_file(vminspect->profile);
    if ( !json )
    {
        printf("%s: Cannot open profile %s\n", __FUNCTION__, vminspect->profile);
        goto err;
    }

    if ( !json_object_object_get_ex(json, REKALL_CONSTANTS, &json_syms) )
    {
        printf("%s: Cannot find section %s\n", __FUNCTION__, REKALL_CONSTANTS);
        goto err;
    }

    vminspect->nr_syms = json_object_object_length(json_syms);
    
    vminspect->syms = malloc(sizeof(struct symbol) * vminspect->nr_syms); 
    if ( !vminspect->syms )
        goto err_syms;
    memset(vminspect->syms, 0, sizeof(struct symbol) * vminspect->nr_syms);

    json_object_object_foreach(json_syms, key, val)
    {
        vminspect->syms[i].address = (uint64_t) json_object_get_int64(val);
        vminspect->syms[i].name = strdup(key);

        if ( !vminspect->syms[i].name )
            goto err_syms;

        /* Maintain canonical addresses only */
        if ( VMI_GET_BIT(vminspect->syms[i].address, 47) )
            vminspect->syms[i].address |= 0xffff000000000000UL;

        //printf("%s : 0x%lx\n", vminspect->syms[i].name, vminspect->syms[i].address);

        i++;
    }

    if ( json )
        json_object_put(json);

    ret = 0;
    return ret;

err_syms:
    cleanup_profile(vminspect);
err:
    if ( json )
        json_object_put(json);

    return ret;
}

static int profile_init_platform(struct vminspect *vminspect)
{
    int ret = -1;
    json_object *json;
    json_object *json_metadata, *json_class, *json_arch;
    const char *os, *arch; 
    
    json = json_object_from_file(vminspect->profile);
    if ( !json )
    {
        printf("%s: Cannot open profile %s\n", __FUNCTION__, vminspect->profile);
        goto err;
    }

    if ( !json_object_object_get_ex(json, REKALL_METADATA, &json_metadata) )
    {
        printf("%s: Cannot find section %s\n", __FUNCTION__, REKALL_METADATA);
        goto err;
    }

    if ( !json_object_object_get_ex(json_metadata, REKALL_METADATA_PROFILECLASS, &json_class) )
    {
        printf("%s: Cannot find section %s\n", __FUNCTION__, REKALL_METADATA_PROFILECLASS);
        goto err;
    }

    if ( !json_object_object_get_ex(json_metadata, REKALL_METADATA_ARCH, &json_arch) )
    {
        printf("%s: Cannot find section %s\n", __FUNCTION__, REKALL_METADATA_ARCH);
        goto err;
    }

    os = json_object_get_string(json_class);

    if ( !strcmp(os, "Linux") )
        vminspect->os = VMI_OS_LINUX;
    else if ( !strcmp(os, "Ntkrnlmp") )
        vminspect->os = VMI_OS_WINDOWS;
    else if ( !strcmp(os, "Ntkrpamp") )
        vminspect->os = VMI_OS_WINDOWS;

    arch = json_object_get_string(json_arch);

    if ( !strcmp(arch, "arm") )
        vminspect->arch = VMI_ARCH_ARM32;
    else
        vminspect->arch = VMI_ARCH_UNKNOWN;

    ret = 0;
err:
    if ( json )
        json_object_put(json);

    return ret;
}

int init_profile(struct vminspect *vminspect)
{
    int ret;
    
    ret = profile_init_platform(vminspect); 
    if ( ret )
        goto err;

    printf("Platform: %s on %s\n",
           (vminspect->os == VMI_OS_LINUX) ? "Linux" : "Windows",
           (vminspect->arch == VMI_ARCH_ARM32) ? "AArch32" : "Unknown");

    ret = profile_init_syms(vminspect); 
    if ( ret )
        goto err;

    printf("Symbols found: %d\n", vminspect->nr_syms);

    ret = profile_init_syscalls(vminspect); 
    if ( ret )
        goto err;

    printf("System calls considered: %d\n", vminspect->nr_syscalls);

err:
    return ret;
}

void cleanup_profile(struct vminspect *vminspect)
{
    int i;

#if 0
    if ( vminspect->syscalls )
        tdestroy(vminspect->syscalls, free);
#endif

    if ( vminspect->syms )
    {
        for ( i=0; i<vminspect->nr_syms; i++ )
        {
            if ( vminspect->syms[i].name )
                free(vminspect->syms[i].name);
        }

        free(vminspect->syms);
    }
}

#include <libxl_utils.h>

#include "vminspect.h"
#include "xen-access.h"

static int xen_access_init_interface(struct xen_control *xc)
{
    xc->xch = xc_interface_open(NULL, NULL, 0);
    if ( !xc->xch )
    {
        printf("%s: Cannot open Xen interface\n", __FUNCTION__);
        goto err;
    }

    xc->xce = xenevtchn_open(NULL, 0);
    if ( !xc->xce )
    {
        printf("%s: Cannot open event channel\n", __FUNCTION__);
        goto err;
    }

    if ( libxl_ctx_alloc(&xc->xlh, LIBXL_VERSION, 0, NULL) )
    {
        printf("%s: Cannot create libxl context\n", __FUNCTION__);
        goto err;
    }

    return 0;

err:
    cleanup_xen_access(xc);

    return -1;
}

int init_xen_access(struct xen_control *xc, char *domain)
{
    if ( xen_access_init_interface(xc) )
        return -1;

    if ( libxl_name_to_domid(xc->xlh, domain, &xc->domain_id) )
    {
        printf("%s: Cannot find domain %s\n", __FUNCTION__, domain);
        return -1;
    }

    printf("Established connection to domain %s with ID %d\n", domain, xc->domain_id);

    return 0;
}

void cleanup_xen_access(struct xen_control *xc)
{
    int ret;
   
    if ( xc->xlh )
    {
        ret = libxl_ctx_free(xc->xlh);
        if ( ret )
            printf("%s: Cannot close connection to libxl\n", __FUNCTION__);

        xc->xlh = NULL;
    }

    if ( xc->xce )
    {
        ret = xenevtchn_close(xc->xce);
        if ( ret )
            printf("%s: Cannot close event channel to Xen\n", __FUNCTION__);

        xc->xce = NULL;
    }

    if ( xc->xch )
    {
        ret = xc_interface_close(xc->xch);
        if ( ret )
            printf("%s: Cannot close connection to Xen\n", __FUNCTION__);

        xc->xch = NULL;
    }   
}

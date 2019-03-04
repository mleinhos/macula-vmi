#include <inttypes.h>
#include <stdlib.h>

#include "vmi.h"

/* XXX: Testing callback on CR3 write access */
static event_response_t vmi_callback_cr3(vmi_instance_t vmi, vmi_event_t* event)
{
    vmi_pid_t pid = -1;

    vmi_dtb_to_pid(vmi, event->reg_event.value, &pid);
    printf("PID %i with CR3=0x%"PRIx64" on vcpu %"PRIu32". Previous CR3=0x%"PRIx64"\n",
            pid, event->reg_event.value, event->vcpu_id, event->reg_event.previous);

    return 0;
}

static int vmi_init_events(struct vminspect *vminspect)
{
    status_t status;

    /* Register CR3 event (x86) */
    memset(&vminspect->event_cr3, 0, sizeof(vmi_event_t));
    SETUP_REG_EVENT(&vminspect->event_cr3, CR3, VMI_REGACCESS_W, 0, vmi_callback_cr3);

    status = vmi_register_event(vminspect->vmi, &vminspect->event_cr3);
    if ( status == VMI_FAILURE )
        printf("%s: Cannot register CR3 event\n", __FUNCTION__);

    return 0;
}

static void vmi_cleanup_events(struct vminspect *vminspect)
{
    if ( vmi_are_events_pending(vminspect->vmi) > 0 )
        vmi_events_listen(vminspect->vmi, 0);

    vmi_clear_event(vminspect->vmi, &vminspect->event_int3, NULL);
    vmi_clear_event(vminspect->vmi, &vminspect->event_cr3, NULL);
}

static int vmi_init_libvmi(struct vminspect *vminspect)
{
    status_t ret;
    vmi_init_data_t *init_data = malloc(sizeof(vmi_init_data_t) +
                                        sizeof(vmi_init_data_entry_t));
    if ( !init_data )
        return -1;

    init_data->count = 1;
    init_data->entry[0].type = VMI_INIT_DATA_XEN_EVTCHN;
    init_data->entry[0].data = (void*) vminspect->xc.xce;

    ret = vmi_init(&vminspect->vmi, VMI_XEN, &vminspect->xc.domain_id,
                   VMI_INIT_DOMAINID|VMI_INIT_EVENTS, init_data, NULL);
    free(init_data);
    if ( ret == VMI_FAILURE )
    {
        printf("%s Cannot initialize LibVMI\n", __FUNCTION__);
        return -1;
    }

    /* TODO: Do we need to initialize paging and OS for LibVMI? */

    return 0;
}

static int vmi_init_altp2m(struct vminspect *vminspect)
{
    int ret;
    xc_interface *xch = vminspect->xc.xch;
    uint32_t domain_id = vminspect->xc.domain_id;

    ret = xc_altp2m_set_domain_state(xch, domain_id, 1);
    if ( ret )
    {
        printf("%s: Cannot enable altp2m on domain %d\n", __FUNCTION__, domain_id);
        goto err;
    }

    ret = xc_altp2m_create_view(xch, domain_id, 0, &vminspect->altp2m_r_view);
    if ( ret )
    {
        printf("%s: Cannot create altp2m view\n", __FUNCTION__);
        goto err;
    }

    printf("Xen altp2m read view created (altp2m[%d])\n", vminspect->altp2m_r_view);

    ret = xc_altp2m_create_view(xch, domain_id, 0, &vminspect->altp2m_x_view);
    if ( ret )
    {
        printf("%s: Cannot create altp2m view\n", __FUNCTION__);
        goto err;
    }

    printf("Xen altp2m execute view created (altp2m[%d])\n", vminspect->altp2m_x_view);

    ret = xc_altp2m_switch_to_view(xch, domain_id, vminspect->altp2m_x_view);
    if ( ret )
    {
        printf("%s: Cannot switch to altp2m execute view (altp2m[%d])\n",
                __FUNCTION__, vminspect->altp2m_x_view);
        goto err;
    }

    printf("Switched to Xen altp2m execute view (altp2m[%d])\n", vminspect->altp2m_x_view);

    return 0;

err:
    cleanup_vmi(vminspect);

    return -1;
}

int init_vmi(struct vminspect *vminspect)
{
    int ret;

    ret = vmi_init_libvmi(vminspect);
    if ( ret )
        goto err;

    ret = vmi_init_altp2m(vminspect);
    if ( ret )
        goto err;

    ret = vmi_init_events(vminspect);
    if ( ret )
        goto err;

    return 0;
err:
    cleanup_vmi(vminspect);

    return -1;
}

void cleanup_vmi(struct vminspect *vminspect)
{
    int ret;
    xc_interface *xch = vminspect->xc.xch;
    uint32_t domain_id = vminspect->xc.domain_id;

    vmi_pause_vm(vminspect->vmi);
    vmi_cleanup_events(vminspect);
    vmi_resume_vm(vminspect->vmi);

    ret = xc_altp2m_switch_to_view(xch, domain_id, 0);
    if ( ret )
        printf("%s: Cannot switch to altp2m[0]\n", __FUNCTION__);

    if ( vminspect->altp2m_r_view )
        xc_altp2m_destroy_view(xch, domain_id, vminspect->altp2m_r_view);
    if ( vminspect->altp2m_x_view )
        xc_altp2m_destroy_view(xch, domain_id, vminspect->altp2m_x_view);

    ret = xc_altp2m_set_domain_state(xch, domain_id, 0);
    if ( ret )
        printf("%s: Cannot disable altp2m on domain %d\n", __FUNCTION__, domain_id);

    if ( vminspect->vmi )
    {
        vmi_destroy(vminspect->vmi);
        vminspect->vmi = NULL;
    }
}

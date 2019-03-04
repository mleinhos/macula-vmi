#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "profile.h"
#include "vminspect.h"
#include "vmi.h"

static struct vminspect vminspect = { 0 };
static int interrupted = 0;

static void exit_handler(int sig)
{
    interrupted = sig;
}

void free_resources(void)
{
    cleanup_vmi(&vminspect);
    cleanup_xen_access(&vminspect.xc);
    cleanup_profile(&vminspect);
}

void usage(char *pname)
{
    printf("Usage: %s [OPTION]\n", pname);
}

int main(int argc, char *argv[])
{
    int c, ret;
    status_t status;
    struct sigaction act;

    /* Setup exit handler */
    act.sa_handler = exit_handler;
    act.sa_flags = 0;

    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    while ( 1 )
    {
        int option_index = 0;
        static struct option options[] =
        {
            {"domain",  required_argument, 0, 'd'},
            {"profile", required_argument, 0, 'p'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "d:p:", options, &option_index);
        if ( c == -1 )
            break;

        switch (c)
        {
        case 'd':
            vminspect.domain = optarg;
            break;
        case 'p':
            vminspect.profile = optarg;
            break;
        default:
            usage(argv[0]);
            free_resources();
            exit(EXIT_FAILURE);
        }
    }

    if ( !vminspect.domain )
    {
        printf("Missing domain name\n");
        goto error;
    }

    if ( !vminspect.profile )
    {
        printf("Missing domain name\n");
        goto error;
    }

    /* Parse and prepare the Rekall profile */
    ret = init_profile(&vminspect);
    if ( ret )
        goto error;

    /* Prepare the interface to Xen */
    ret = init_xen_access(&vminspect.xc, vminspect.domain);
    if ( ret )
        goto error;

    /* Initialize LibVMI and Xen altp2m */
    ret = init_vmi(&vminspect);
    if ( ret )
        goto error;

    while ( !interrupted ) {
        printf("Waiting for events\n");
        status = vmi_events_listen(vminspect.vmi,500);
        if ( status != VMI_SUCCESS )
        {
            printf("Exiting\n");
            interrupted = -1;
        }
    }

    free_resources();

    return EXIT_SUCCESS;

error:
    free_resources();
    exit(EXIT_FAILURE);
}

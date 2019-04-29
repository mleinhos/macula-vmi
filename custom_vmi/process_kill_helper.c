/*
 * Description: facilitates process killing by reading pid out of
 * file. Also, contains disabled code for scanning for victim process
 * and corrupting it.
 *
 * Author: Matt Leinhos
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <libvmi/libvmi.h>

int
get_pid_from_file(const char* path,
                  vmi_pid_t* pid)
{
	int rc = 0;
	char pidstr[20] = {0};
	FILE* pidfile = NULL;
	long int pidval = 0;

	pidfile = fopen(path, "r");
	if (NULL == pidfile)
	{
		rc = errno;
		perror("fopen");
		goto exit;
	}

	if (fread(pidstr, 1, sizeof(pidstr), pidfile) < 1)
	{
		rc = errno;
		printf("File %s is too short\n", path);
		goto exit;
	}

	pidval = strtol(pidstr, NULL, 10);
	if (LONG_MIN == pidval ||
            LONG_MAX == pidval  )
	{
		rc = errno;
		printf("File %s has invalid contents\n", path);
		goto exit;
	}

	printf("Read pid %ld from %s\n", pidval, path);
	*pid = pidval;

exit:
	if (NULL != pidfile)
	{
		fclose(pidfile);
	}

	return rc;
}

/*
// set task.mm.pgd to 0
static status_t
do_murder_process (vmi_instance_t vmi,
                   json_object* rekall_profile,
                   addr_t task_struct)
{
    addr_t task_mm_ofs = 0;
    addr_t mm_pgd_ofs = 0;

    addr_t mm = 0;
    addr_t mm_pgd = 0;

    addr_t new_pgd = 0;

    status_t status = VMI_SUCCESS;

    if (!rekall_get_struct_member_rva(rekall_profile, "task_struct", "mm", &task_mm_ofs))
    {
        fprintf(stderr, "Can't find offset of task_struct.mm\n");
        status = VMI_FAILURE;
    }

    if (!rekall_get_struct_member_rva(rekall_profile, "mm_struct", "pgd", &mm_pgd_ofs))
    {
        fprintf(stderr, "Can't find offset of mm_struct.pgd\n");
        status = VMI_FAILURE;
    }

    status = vmi_read_addr_va(vmi, task_struct + task_mm_ofs, 0, &mm);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to read task.mm.\n");
        goto exit;
    }

    status = vmi_read_addr_va(vmi, mm + mm_pgd_ofs, 0, &mm_pgd);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to read mm.pgd.\n");
        goto exit;
    }

    // Now, overwrite the pgd in the mm_struct
    status = vmi_write_va(vmi, mm_pgd, 0, sizeof(addr_t), &new_pgd, NULL);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to write mm.pgd.\n");
        goto exit;
    }

exit:
//    asm("int $3;");
    return status;
}

static status_t
do_murder_process2 (vmi_instance_t vmi,
                    json_object* rekall_profile,
                    addr_t task_struct)
{
    addr_t task_tif_ofs = 0;
    addr_t tif_flags_ofs = 0;

    addr_t task_pending_ofs = 0;
    addr_t pending_signal_ofs = 0;

    uint64_t flags_val = 0;
    uint64_t signal_val = 0;

    status_t status = VMI_SUCCESS;

    // N.B. thread_info may be embedded in the task_struct, depending on kernel config
//    asm("int $3;");

    if (!rekall_get_struct_member_rva(rekall_profile, "task_struct", "thread_info", &task_tif_ofs))
    {
        fprintf(stderr, "Can't find offset of task_struct.thread_info\n");
        status = VMI_FAILURE;
    }
    if (!rekall_get_struct_member_rva(rekall_profile, "task_struct", "pending", &task_pending_ofs))
    {
        fprintf(stderr, "Can't find offset of task_struct.pending\n");
        status = VMI_FAILURE;
    }
    if (!rekall_get_struct_member_rva(rekall_profile, "sigpending", "signal", &pending_signal_ofs))
    {
        fprintf(stderr, "Can't find offset of sigpending.signal\n");
        status = VMI_FAILURE;
    }
    if (!rekall_get_struct_member_rva(rekall_profile, "thread_info", "flags", &tif_flags_ofs))
    {
        fprintf(stderr, "Can't find offset of thread_info.flags\n");
        status = VMI_FAILURE;
    }
    if (VMI_FAILURE == status)
    {
        goto exit;
    }

    status = vmi_read_64_va(vmi, task_struct + task_tif_ofs + tif_flags_ofs, 0, &flags_val);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to read task.thread_info.flags.\n");
        goto exit;
    }

    status = vmi_read_64_va(vmi, task_struct + task_pending_ofs + pending_signal_ofs, 0, &signal_val);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to read task.pending.signal.\n");
        goto exit;
    }

    // Add a signal pending to the flags
    flags_val |= 1;
    signal_val = ~0;

    status = vmi_write_64_va(vmi, task_struct + task_tif_ofs + tif_flags_ofs, 0, &flags_val);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to write tif.flags.\n");
        goto exit;
    }

    status = vmi_write_64_va(vmi, task_struct + task_pending_ofs + pending_signal_ofs, 0, &flags_val);
    if (VMI_FAILURE == status)
    {
        fprintf(stderr, "Failed to write task.pending.signal.\n");
        goto exit;
    }

exit:
//    asm("int $3;");
    return status;
}


// process_kill() routine, based on libvmi (vs drakvuf) as much as practical
// Steps:
//   Find task_struct T with matching .pid field
//   Corrupt T->mm->pgd Pull out its mm_struct field
//
// Another option is to assert TIF_SIGPENDING in T->thread_info.
//
// See libvmi process-list.c for exemplar

status_t
process_kill(vmi_instance_t vmi,
             json_object* rekall_profile,
             vmi_pid_t victim_pid)
{

    addr_t task_tasks_ofs = 0;
    addr_t task_pid_ofs = 0;
    addr_t task_name_ofs = 0;

    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    addr_t current_process = 0;

    vmi_pid_t pid = 0;
    int rc = 0;
    status_t status = VMI_SUCCESS;

    char* procname = NULL;

    if (VMI_OS_LINUX != vmi_get_ostype(vmi))
    {
        fprintf(stderr, "Linux OS not detected.\n");
        status = VMI_FAILURE;
    }
    if (!rekall_get_struct_member_rva(rekall_profile, "task_struct", "tasks", &task_tasks_ofs))
    {
        fprintf(stderr, "Can't find offset of task_struct.tasks\n");
        status = VMI_FAILURE;
    }
    if (!rekall_get_struct_member_rva(rekall_profile, "task_struct", "pid", &task_pid_ofs))
    {
        fprintf(stderr, "Can't find offset of task_struct.pid\n");
        status = VMI_FAILURE;
    }
    if (!rekall_get_struct_member_rva(rekall_profile, "task_struct", "comm", &task_name_ofs))
    {
        fprintf(stderr, "Can't find offset of task_struct.name\n");
        status = VMI_FAILURE;
    }
    if (VMI_FAILURE == status)
    {
        goto exit;
    }

    status = vmi_translate_ksym2v(vmi, "init_task", &list_head);
    if ( VMI_FAILURE == status )
    {
        fprintf(stderr, "init_task not found\n");
        goto exit;
    }

    list_head += task_tasks_ofs;
    cur_list_entry = list_head;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry))
    {
        printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
        goto exit;
    }

    // walk the task list
    while (1)
    {

        current_process = cur_list_entry - task_tasks_ofs;

        vmi_read_32_va(vmi, current_process + task_pid_ofs, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + task_name_ofs, 0);
        if (!procname)
        {
            printf("Failed to find procname\n");
            goto exit;
        }

        // print out the process name
        printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
        free(procname);
        procname = NULL;

        if (victim_pid == pid)
        {
            printf("^^^^ This process matches. Attempting to kill it.\n");
            if (0)
            {
                status = do_murder_process(vmi, rekall_profile, current_process);
            }
            else
            {
                status = do_murder_process2 (vmi, rekall_profile, current_process);
            }

            if (VMI_FAILURE == status)
            {
                goto exit;
            }
        }

        // follow the next pointer
        cur_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE)
        {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", cur_list_entry);
            goto exit;
        }
        if (cur_list_entry == list_head)
        {
            break;
        }
    }

exit:
//    asm("int $3;");

    return rc;
}
*/


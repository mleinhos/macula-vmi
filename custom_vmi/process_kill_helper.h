#ifndef process_kill_helper_h
#define process_kill_helper_h

#ifdef __cplusplus
extern "C" {
#endif

#include <libvmi/libvmi.h>
#include <json-c/json.h>

#define PID_FILE_LOC "/tmp/pidfile"
#define KILL_PID_NONE ((vmi_pid_t)-1)


int
get_pid_from_file(const char* path,
                  vmi_pid_t* pid);
/*
  int
  process_kill(vmi_instance_t vmi,
  json_object* rekall_profile,
  vmi_pid_t pid);
*/

#ifdef __cplusplus
}
#endif

#endif // process_kill_helper_h

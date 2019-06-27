/*
 * File: nvmi-iface.h
 *
 * Purpose: Defines the data types and constants that are passed
 *          between the VMI and controller components of the Ninspect
 *          system.
 *
 * Notes: User must provide byte-sized types, e.g. uint8_t, int64_t,
 *        etc.
 *
 * Author: Matt Leinhos
 *
 * THIS IS INCOMPLETE, AND MEANT TO SHOW THE DESIGN ONLY.
 */

#ifndef nvmi_public_defs_t
#define nvmi_public_defs_t

// General defs
#define PROCESS_MAX_COMM_NAME 32 // max len of comm field in task_struct
#define PROCESS_MAX_PATH 128

#define SYSCALL_MAX_NAME_LEN 32
#define SYSCALL_MAX_ARGS 6
#define SYSCALL_MAX_ARG_BUF 1024

#define SOCKADDR_MAX_LEN 64 // TODO: get sizeof(struct sockaddr_in6)

#define NVMI_STRUCT_ATTRIBS __attribute__((packed))


//typedef uint32_t length_t;

// Our file descriptor: reduced in size for typical case
typedef uint32_t nvmi_fd_t;


// These indicate there's no data to point to
//#define INVALID_LENGTH ((length_t)-1)
//#define INVALID_OFFSET ((length_t)-1)
#define INVALID_FILE_DESCRIPTOR ((nvmi_fd_t)-1)

// Process ID: guaranteed unique during process lifetime. Once a
// process has died, its ID may be reused. This isn't necessarily the
// PID.
typedef uint64_t process_ident_t;


// Timestamp: is this adequate?
typedef struct _timeval
{
	uint64_t sec;
	uint64_t usec;
} NVMI_STRUCT_ATTRIBS timeval_t;


typedef struct _sock_addr
{
	uint16_t family;
	uint8_t  data[SOCKADDR_MAX_LEN];
} NVMI_STRUCT_ATTRIBS sock_addr_t;


typedef struct _arg_type_fdset
{
	nvmi_fd_t fd;
} NVMI_STRUCT_ATTRIBS arg_type_fdset_t;


typedef struct _arg_type_pollfd
{
	nvmi_fd_t fd;
	uint16_t  events;
} NVMI_STRUCT_ATTRIBS arg_type_pollfd_t;


enum event_types
{
	EVENT_TYPE_NONE           = 0,
	EVENT_TYPE_SYSCALL        = 1,
	EVENT_TYPE_PROCESS_CREATE = 2, // process created, or first observed (before execve)
	EVENT_TYPE_PROCESS_DEATH  = 3, // process died (do_exit called)
	EVENT_TYPE_FILE_CREATE    = 4,
};

typedef uint32_t event_type_t;

//
// Process create event -- relayed upon first event seen from process
// -- not necessarily upon process creation.
//

typedef struct _process_creation_event
{
	uint64_t uid;
	uint64_t gid;
	uint64_t pid;
	char     comm[PROCESS_MAX_COMM_NAME];
	char     path[PROCESS_MAX_PATH];
	char     pwd[PROCESS_MAX_PATH];
} NVMI_STRUCT_ATTRIBS process_creation_event_t;


//
// Process death event
//

typedef struct _process_death_event
{
	uint32_t status; // ignored
} NVMI_STRUCT_ATTRIBS process_death_event_t;


typedef struct _file_creation_event
{
	uint32_t file_no;
} NVMI_STRUCT_ATTRIBS file_creation_event_t;


//
// Syscall event
//

enum syscall_arg_type
{
	// Scalar types: values held in syscall event's args
	SYSCALL_ARG_TYPE_NONE   = 0,
	SYSCALL_ARG_TYPE_SCALAR = 1, // includes bool, short, and int; signed and unsigned
	SYSCALL_ARG_TYPE_PVOID  = 2, // void * - a pointer, but not dereferenced

	// Array types: values held in syscall event's data 
	SYSCALL_ARG_TYPE_STR      = 20, // char *
	SYSCALL_ARG_TYPE_WSTR     = 21, // wide char *
	SYSCALL_ARG_TYPE_SOCKADDR = 22, // sock_addr_t *, resolved
	SYSCALL_ARG_TYPE_POLLFD   = 23,
	SYSCALL_ARG_TYPE_FDSET    = 24,

}; // syscall_arg_type_t;

typedef uint32_t syscall_arg_type_t;

typedef struct _syscall_arg_t {
	syscall_arg_type_t type;
	uint32_t           len; // Valid only in case of complex data type

	union
	{
		uint64_t  long_val;

		// In case of a complex type, its offset in the data buffer is here
		uint64_t offset;
	} val;
} NVMI_STRUCT_ATTRIBS syscall_arg_t;


// Flags for syscall events

// This syscall event contains a variable-length buffer
#define SYSCALL_EVENT_FLAG_HAS_BUFFER   0x0001 

// The syscall accepted a buffer too long for us to process completely
#define SYSCALL_EVENT_FLAG_BUFFER_TRUNCATED 0x0002

// All the consumable bits in the event flags are within this mask...
#define SYSCALL_EVENT_EXTERNAL_MASK 0xffff

typedef uint32_t syscall_flags_t;

typedef struct _syscall_event
{
	char           name[SYSCALL_MAX_NAME_LEN];
	uint32_t       flags;
	uint32_t       arg_ct;
	syscall_arg_t  args[SYSCALL_MAX_ARGS];

	// Variable-length data associated with this syscall event
	uint8_t             data[SYSCALL_MAX_ARG_BUF];
} NVMI_STRUCT_ATTRIBS syscall_event_t;


// Every event will take this form...
typedef struct _event_t
{
	uint32_t        len;
	uint32_t        type;
	uint64_t        id;
	process_ident_t context;
	timeval_t       time;
	char            comm[PROCESS_MAX_COMM_NAME];

	union {
		process_creation_event_t pcreate;
		process_death_event_t    pdeath;
		file_creation_event_t    fcreate;
		syscall_event_t          syscall;
	} u;

} NVMI_STRUCT_ATTRIBS event_t;


// Description of a request sent from the controller to the VMI component

enum request_codes
{
	REQUEST_CMD_NONE = 0,
	REQUEST_CMD_PROCKILL = 1,
	REQUEST_CMD_SET_EVENT_LIMIT = 2,
	REQUEST_CMD_GET_PROC_CONTEXT = 3,
};
typedef uint32_t request_code_t;


typedef struct _request_t
{
	uint64_t       id;
	request_code_t cmd;
	uint64_t       arg1;
	uint64_t       arg2;
} NVMI_STRUCT_ATTRIBS request_t;


// Response to request: id fields match
// TODO: expand to enable info queries, e.g. GET_PROC_CONTEXT
typedef struct _response
{
	uint64_t id;
	uint32_t status; // 0 on success, otherwise a positive errno value
} NVMI_STRUCT_ATTRIBS response_t;


#endif // nvmi_public_defs_t

/*
 * Local variables:
 * mode: C
 * c-file-style: "linux"
 * End:
 */

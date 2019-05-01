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

#ifndef nvmi_iface_t
#define nvmi_iface_t

// General defs
#define PROCESS_MAX_PATH 128
#define SYSCALL_MAX_ARGS 6


#define NVMI_STRUCT_ATTRIBS __attribute__((packed))



typedef uint16_t length_t;
typedef uint16_t offset_t;

// These indicate there's no data to point to
#define INVALID_LENGTH ((length_t)-3);
#define INVALID_OFFSET ((length_t)-3);


// Process ID: guaranteed unique during process lifetime. Once a
// process has died, its ID may be reused. This isn't necessarily the
// PID.
typedef uint64_t process_ident_t;

// Timestamp: is this adequate?
typedef struct _timeval {
    uint64_t sec;
    uint64_t usec;
} NVMI_STRUCT_ATTRIBS  timeval_t;


typedef struct _sock_addr {
    uint16_t family;
    uint8_t  data[14];
} NVMI_STRUCT_ATTRIBS sock_addr_t;


enum event_types {
    EVENT_TYPE_NONE = 0,
    EVENT_TYPE_SYSCALL = 1,
    EVENT_TYPE_PROCESS_CREATE = 2,
    EVENT_TYPE_PROCESS_DEATH = 3,
    EVENT_TYPE_FILE_CREATION = 4,
};

typedef uint8_t event_type_t;

//
// Process create event -- relayed upon first event seen from process
// -- not necessarily upon process creation.
//

typedef struct _process_creation_event {
    uint64_t pdb; // page directory base
    uint64_t uid;
    uint64_t gid;
    uint64_t pid;
    char path[PROCESS_MAX_PATH];
} NVMI_STRUCT_ATTRIBS process_creation_event_t;


//
// Process death event
//

typedef struct _process_death_event {
    uint32_t status; // ignored
} NVMI_STRUCT_ATTRIBS process_death_event_t;


typedef struct _file_creation_event {
    uint32_t file_no;
} NVMI_STRUCT_ATTRIBS file_creation_event_t;


//
// Syscall event
//

// Syscall numbers: not necessarily tied to those used by system
enum syscall_numbers {
    SYSCALL_NONE   = 0,
    SYSCALL_OPEN   = 1,
    SYSCALL_OPENAT = 2,
    SYSCALL_READ   = 3,
    SYSCALL_WRITE  = 4,
    // etc etc .....
};

typedef uint16_t syscall_number_t;

enum syscall_arg_types {
    // Scalar types: values held in syscall event's args
    SYSCALL_ARG_TYPE_NONE   = 0,
    SYSCALL_ARG_TYPE_INT    = 1, // includes bool, short, and int; signed and unsigned
    SYSCALL_ARG_TYPE_LONG   = 2, // large enough to hold address, maybe merge with int?
    SYSCALL_ARG_TYPE_CHAR   = 3, // one char
    SYSCALL_ARG_TYPE_PVOID  = 4, // void *

    // Array types: values held in syscall event's data 
    SYSCALL_ARG_TYPE_PCHAR    = 20, // char *
    SYSCALL_ARG_TYPE_WCHAR    = 21, // one wide char
    SYSCALL_ARG_TYPE_PWCHAR   = 22, // wchar *
    SYSCALL_ARG_TYPE_SOCKADDR = 23, // sock_addr_t *
};

typedef uint8_t syscall_arg_type_t;

typedef struct _syscall_arg_t {
    syscall_arg_type_t type;
    length_t           len; // Valid only in case of complex data type

    union {
	int   int_val;
	long  long_val;
	char  char_val;

	// In case of a complex type, its offset in the data buffer is here
	offset_t offset;
    } val;
} NVMI_STRUCT_ATTRIBS syscall_arg_t;


// Flags for syscall events

// This syscall event contains a variable-length buffer
#define SYSCALL_EVENT_FLAG_HAS_BUFFER   0x0001 

// The syscall accepted a buffer too long for us to process completely
#define SYSCALL_EVENT_FLAG_BUFFER_TRUNCATED 0x0002

// All the consumable bits in the event flags are within this mask...
#define SYSCALL_EVENT_EXTERNAL_MASK 0xff

typedef uint32_t syscall_flags_t;

typedef struct _syscall_event {
    syscall_number_t    num;
    syscall_flags_t     flags;
    syscall_arg_count_t arg_ct;
    syscall_arg_t       args[SYSCALL_MAX_ARGS];

    // Variable-length data associated with this syscall event
    uint8_t             data[1];
} NVMI_STRUCT_ATTRIBS syscall_event_t;


// Every event will take this form...
typedef struct _event_t {
    uint32_t        event_len;
    event_type_t    event_type;
    process_ident_t context;
    timeval_t       time;

    union {
	process_death_event_t death;
	file_creation_event_t newfile;
	syscall_event_t       syscall;
    } u;

} NVMI_STRUCT_ATTRIBS event_t;


// Description of a request sent from the controller to the VMI component

enum request_codes {
    REQUEST_TYPE_NONE = 0,
    REQUEST_TYPE_PROCKILL = 1,
};
typedef uint16_t request_code_t;


typedef struct _request_t {
    request_code_t code;
    uint64_t       request_id;
    uint64_t       arg1;
    uint64_t       arg2;
} NVMI_STRUCT_ATTRIBS request_t;


// Response to request
typedef struct _response {
    uint64_t request_id;
    uint32_t status;
} NVMI_STRUCT_ATTRIBS response_t;


#endif // nvmi_iface_t

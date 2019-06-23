#!/usr/bin/env python3

##
## Provides interface to NInspector via ZMQ channels.
##

##
## Events represent syscalls that occured on the DomU, and are
## returned to the caller as dictionaries with these keys:
##  - id - a domU-unique (within constraints of 64-bit value) ID of the event
##  - time - time of event
##  - pid - PID where event occured
##  - pname - process name where event occured
##  - type - the type of event:  "syscall", "proc_create", "proc_death", or "file_create"

import time
import zmq
import struct
import struct

syscall_ct = dict() # map PID --> calls seen

# Header for every event
evt_fmt = "IIQQQQ32s"

#
# Syscall event format:
#
evt_syscall_fmt = "32sII"

# Syscall arguments: a single arg looks like this...
evt_syscall_arg_fmt = "IIQ"
# ... and altogether here's the format, followed by a data buffer
evt_syscall_args = 6 * evt_syscall_arg_fmt



SYSCALL_EVENT_FLAG_HAS_BUFFER       = 0x0001
SYSCALL_EVENT_FLAG_BUFFER_TRUNCATED = 0x0002

EVENT_TYPE_NONE           = 0
EVENT_TYPE_SYSCALL        = 1
EVENT_TYPE_PROCESS_CREATE = 2
EVENT_TYPE_PROCESS_DEATH  = 3
EVENT_TYPE_FILE_CREATION  = 4

SYSCALL_ARG_TYPE_NONE   = 0
SYSCALL_ARG_TYPE_SCALAR = 1
SYSCALL_ARG_TYPE_PVOID  = 2

SYSCALL_ARG_TYPE_STR      = 20
SYSCALL_ARG_TYPE_WSTR     = 21
SYSCALL_ARG_TYPE_SOCKADDR = 22

REQUEST_TYPE_NONE = 0
REQUEST_TYPE_PROCKILL = 1
REQUEST_TYPE_SET_EVENT_LIMIT = 2


class nvmi_iface:
    def __init__(self, event_channel, request_channel):
        self.echannel = event_channel
        self.rchannel = request_channel
        self.ecount = 0
        self._request_id = 1 # starting request ID
        self.pending_kills = dict() # maps: PID -> request id

    def _get_next_request_id(self):
        while 0 == self._request_id:
            self._request_id += 1

        return self._request_id

    def _decode_str_bytes(self, data):
        try:
            return data.decode('utf-8', 'replace').rstrip('\0')
        except UnicodeDecodeError as e:
                print ("Encountered invalid encoding in {}".format(data))
                import pdb;pdb.set_trace()
                return None

    def get_event(self):
        msg = self.echannel.recv()
        rval = dict() # returned to caller
        ofs = 0

        while True:
            try:
                (elen, etype, eid, epid, ets_s, ets_us, ecomm) = \
                    struct.unpack("!" + evt_fmt,
                                  msg[0:struct.calcsize(evt_fmt)])

                rval['type']  = {EVENT_TYPE_SYSCALL        : "syscall",
                                 EVENT_TYPE_PROCESS_CREATE : "proc_create",
                                 EVENT_TYPE_PROCESS_DEATH  : "proc_death",
                                 EVENT_TYPE_FILE_CREATION  : "file_create"} [etype]

                rval['id']    = eid
                rval['time']  = ets_s + 1.0 * ets_us / 1000000.
                rval['pid']   = epid
                rval['pname'] = ecomm.decode().rstrip('\0')

                ofs += struct.calcsize(evt_fmt)

                # get syscall info
                if EVENT_TYPE_SYSCALL == etype:
                    (ename, eflags, eargct) = struct.unpack("!" + evt_syscall_fmt,
                                                            msg[ofs:ofs+struct.calcsize(evt_syscall_fmt)])

                    data = msg[struct.calcsize(evt_fmt + evt_syscall_fmt + evt_syscall_args):]
                    ofs += struct.calcsize(evt_syscall_fmt)
                    rval['syscall_name'] = self._decode_str_bytes(ename)

                    args = list()
                    for i in range(eargct):
                        (atype, alen, aval) = struct.unpack("!" + evt_syscall_arg_fmt,
                                                            msg[ofs:ofs+struct.calcsize(evt_syscall_arg_fmt)])
                        ofs += struct.calcsize(evt_syscall_arg_fmt)

                        if atype in (SYSCALL_ARG_TYPE_STR, SYSCALL_ARG_TYPE_WSTR):
                            args.append(self._decode_str_bytes(data[aval: aval + alen]))
                        else:
                            args.append(aval)

                    rval['args'] = args

                self.ecount += 1

                print (rval)

                # store the original message so caller can send it elsewhere if needed
                rval['raw'] = msg
                return rval

            except Exception as  e:
                import pdb;pdb.set_trace()
                print ("Encountered exception {}".format(e))


    def request_proc_kill (self, target_pid):
        if target_pid in self.pending_kills.values():
            print ("Not re-requesting kill of PID {}".format(target_pid))
            return

        _id = self._get_next_request_id()

        data = struct.pack("!QIQQ", _id, REQUEST_TYPE_PROCKILL, target_pid, 0)
        self.rchannel.send(data)
        self.pending_kills [_id] = target_pid

    def request_set_event_count (self, new_count):
        _id = self._get_next_request_id()
        pass

    def pending_requests(self):
        return len(self.pending_kills)

    def get_response(self):
        try:
            data = self.rchannel.recv(zmq.NOBLOCK)
        except zmq.error.Again as e:
            # no data
            return None

        if data:
            response = struct.unpack("!QI", data)
            if data[0] in self.pending_kills:
                del self.pending_kills[data[0]]

            return response
        

if __name__ == '__main__':
    pending_requests = 0
    context = zmq.Context()

    # First, connect our subscriber socket
    monitor = context.socket(zmq.PAIR)
    monitor.connect('tcp://localhost:5555')

    #time.sleep(1)

    requestor = context.socket(zmq.PAIR)
    requestor.bind ('tcp://*:5556')

    nvmi = nvmi_iface (monitor, requestor)

    while True:
        evt = nvmi.get_event()
        print ([evt[k] for k in evt if k is not 'raw'])

        pname = evt['pname']
        pid   = evt['pid']

        syscall_ct[pid] = syscall_ct.get(pid,0) + 1

        if pname in ('ps','w') and syscall_ct[pid] > 10:
            print ("Attempting to kill pid {}".format(pid))
            nvmi.request_proc_kill (pid)
            syscall_ct[pid] = 0
            pending_requests += 1

        if pname in ('nmap') and syscall_ct[pid] > 100:
            print ("Attempting to kill pid {}".format(pid))
            nvmi.request_proc_kill (pid)
            syscall_ct[pid] = 0
            pending_requests += 1

        if nvmi.pending_requests():
            response = nvmi.get_response()
            if response:
                print ("Received response {:x}, status {:d}".format(response[0], response[1]))

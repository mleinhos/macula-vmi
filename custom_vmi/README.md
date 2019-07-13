# NInspector notes

### Introduction

NInspector is an advanced virtual machine introspection (VMI) tool
that can be used in conjunction with NBrain to monitor a virtual
machine (VM) for events of interest from a security perspective. The
tool is built on LibVMI, Rekall, and Xen's altp2m technology. It is
compatible with Intel and ARM.


### Developer notes

Here's how to build NInspector:
* Pull down the latest code:
    ```bash
     git clone git@bitbucket.org:macula/vmi.git
     cd vmi
     git submodule init
     git submodule update
    ```
* Build and install LibVMI. _Note:_ Although LibVMI is included as a submodule to NInspector, the exact version of LibVMI to use is a moving target. Currently we're using:
  * e150ff2a86e1dd6ebb7e78504d2f9090dbce2219 on Intel
  * 6d4c05c152d75b5eca9a060194a806887bec2977 on ARM

* Build NInspector. Within the `vmi` directory, run:
    ```bash
    cd custom_vmi
    make
    ```
  This build process is supported on both Intel and ARM.

* Create the Rekall profile for your target VM. The steps for that are
  outside the scope of this document.

* Note the event log consumption example is
  `vmi/custom_vmi/vmi-iface.py`. This is *not* NBrain, but it provides
  support code for parsing and consuming events produced by
  NInspector.

### Usage notes

The VM you want to monitor must have a LibVMI profile created for
it. For example, you could add an entry in `/etc/libvmi.conf` like

```
stretch {
    ostype = "Linux";
    rekall_profile = "/home/dan/profile-4.15.0-20";
}
```

or even in `vmi/custom_vmi` (assuming you'll run NINspector from that directory):
```
ub18-dev-home {
    ostype = "Linux";
    rekall_profile = "/home/matt/proj/rekall-data/ubuntu-4.15.0-54-generic.json";
}
```

Note that the LibVMI profile *MUST* include the VM's rekall profile.


To get the tool's usage, run it with the `-h` option:
```bash
> ./NInspector -h

Usage:
./NInspector [-v] [-o logfile] [-s] [-d] [-h] <domain name>
	-v Increases verbosity of output logging, can be specified several times.
	-o Specifies file where output logging goes. Default is stderr.
	-s Run in silent mode - do not output events to brain.
	-d Periodically dump callback statistics to logging target.
	-h Print this message and quit.
Notes:
	Rekall profile must be registered in LibVMI profile.
```

A common usage in production would be:
```
./NInspector -o log <domain> 
```

which would direct log messages to a listener and log warnings and
errors to the `log` file.


A common usage in development is:

``` ./NInspector -sv <domain> ```

which would not connect to NBrain or equivalent and would emit
informational, warning, and error messages to stderr.

### Future work

NInspector has untapped potential in the area of policy. It would be
easy to add capabilities in dynamic monitoring, such that the level of
monitoring is increased or reduced based on a number of features, such
as: specific, triggering syscalls or internal kernel functions that
warrant increased monitoring; the number of events seen, either
system-wide or within specific processes, since a triggering event;
interval-based triggers (e.g. periodically increase monitoring to
verify system state).

NInspector's performance can be improved further by offloading more
work out of the event callback path. For instance, it is likely that
user memory can be dereferenced outside of that path. Moreover,
locking might be optimized, depending on future features.

### Bugs
* Syscall arguments cannot be dereferenced on ARM; there are
2 known causes: (1) Xen does not correctly provide the `TTBR0`
register via the event interface; (2) LibVMI does not consistenly find
the page directory base for a process on ARM - in fact, it sometimes
goes into an infinite loop when attempting to do so.

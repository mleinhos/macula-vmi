#!/usr/bin/env bash

##
## PROTOTYPE ONLY -- NOT FOR PRODUCTION
##
## Usage: kill_proc.sh <pid>
##
## Kills the process with the given PID, inside the VM that Ninspector is monitoring.
##
## Assumes:
##  * Well-formed PID is given
##  * Only one instance of Ninspector is running
##
## PROTOTYPE ONLY -- NOT FOR PRODUCTION

echo $1 > /tmp/pidfile
sudo kill -HUP `pidof Ninspector`

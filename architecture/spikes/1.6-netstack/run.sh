#!/bin/sh
. "$(dirname "$0")/../_common/run.sh"
# c 10:200 is /dev/net/tun; the test mknods it (the host needs the tun driver loaded: grep tun /proc/misc).
# The first run downloads the pinned gVisor module, so this spike needs network access once.
spike_run --device-cgroup-rule='c 10:200 rwm'

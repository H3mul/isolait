#!/bin/bash
# Runs inside the throwaway isolait session as the agent. Writes to /workspaces/ws/out. Third-party tools are
# untrusted: they run only here, with the tool directory mounted read-only.
out=/workspaces/ws/out
tools=/workspaces/tools
for i in $(seq 1 100); do [ -x $tools/linpeas ] && break; sleep 0.2; done
[ -x $tools/linpeas ] || { echo "tools directory never appeared" > $out/driver-error; exit 1; }
socks() { find / -xdev \( -path /proc -o -path /sys \) -prune -o -type s -print 2>/dev/null | sort; }
socks > $out/sockets-before.txt
date -u +%FT%TZ > $out/started
uname -r > $out/kernel
timeout 300 $tools/linpeas -N -o system_information,container,cloud,procs_crons_timers_srvcs_sockets,network_information,users_information,software_information > $out/linpeas.txt 2>&1; echo $? > $out/linpeas.exit
timeout 120 bash $tools/deepce -nc > $out/deepce.txt 2>&1; echo $? > $out/deepce.exit
for m in "-recon" "-find-docker" "-find-sockets" "-find-http" "-metadata" "-k8secrets" "-scrape-gcp" "-rev-dns 10.0.2.0/24"; do
	n=${m%% *}; n=${n#-}
	timeout 90 $tools/botb $m > $out/botb-$n.txt 2>&1; echo $? > $out/botb-$n.exit
done
socks > $out/sockets-after.txt
echo done > $out/finished

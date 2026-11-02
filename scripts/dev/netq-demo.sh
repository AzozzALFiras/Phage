#!/usr/bin/env bash
# netq-demo.sh — live proof of per-process network quarantine (the reversible
# "isolate" rung). A service beacon dials out; Phage (enforce) detects the egress
# and severs that process's network WITHOUT killing it — the beacon keeps running
# but can no longer reach its C2. `phage thaw` restores it.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/nq-base.json
LOG=/tmp/nq.log

cleanup(){ pkill -x phaged 2>/dev/null; systemctl stop nq-beacon.service 2>/dev/null; systemctl reset-failed nq-beacon.service 2>/dev/null; for f in $(find /sys/fs/cgroup/phage -name cgroup.procs 2>/dev/null); do :; done; rm -rf /sys/fs/cgroup/phage/netq-* 2>/dev/null; rm -f "$STATE" "$LOG"; }
trap cleanup EXIT

echo "== learn baseline (incl. legitimate HTTPS egress) =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 & LP=$!
sleep 1; for i in $(seq 1 15); do ls / >/dev/null; curl -s -o /dev/null --max-time 2 https://1.1.1.1/ || true; done; sleep 1
kill -INT "$LP" 2>/dev/null; wait "$LP" 2>/dev/null

echo "== start the agent in ENFORCE mode =="
./bin/phaged -bpf "$OBJ" -mode enforce -state "$STATE" >"$LOG" 2>&1 &
sleep 2

echo "== launch a service beacon: dials 1.1.1.1:53 every 2s, logs CONNECTED/BLOCKED =="
systemctl reset-failed nq-beacon.service 2>/dev/null || true
systemd-run --quiet --unit=nq-beacon -p User=nobody \
	bash -c 'for i in $(seq 1 8); do if (exec 3<>/dev/tcp/1.1.1.1/53) 2>/dev/null; then echo "beacon iter $i: CONNECTED"; else echo "beacon iter $i: BLOCKED"; fi; sleep 2; done'
sleep 18

echo
echo "== Phage verdict + action =="
grep -iE "egress|ISOLATED|outbound" "$LOG" | sed 's/^/   /'
echo
echo "== beacon's own view (first dial connects, then C2 is severed) =="
journalctl -u nq-beacon.service --no-pager -o cat 2>/dev/null | sed 's/^/   /'

systemctl stop nq-beacon.service 2>/dev/null; systemctl reset-failed nq-beacon.service 2>/dev/null
echo "== done (the beacon kept running the whole time; only its network was cut) =="

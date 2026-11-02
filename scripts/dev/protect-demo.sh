#!/usr/bin/env bash
# protect-demo.sh — live proof of eBPF-LSM tamper-resistance: an attacker cannot
# kill the agent to blind it. Safe by design: this script's shell is the agent's
# launcher (always allowed to stop it), and pid 1 / reboot always work, so the
# agent can never truly lock the box out.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/protect-base.json
LOG=/tmp/protect.log
PID=""

cleanup(){ [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null; sleep 1; [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null; rm -f "$STATE" "$LOG"; }
trap cleanup EXIT

grep -q bpf /sys/kernel/security/lsm && echo "BPF LSM active: yes" || { echo "no BPF LSM"; exit 1; }

echo "== learn a brief baseline =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 & LP=$!
sleep 1; for i in $(seq 1 8); do ls / >/dev/null; done; sleep 1
kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null

echo "== start the agent WITH -protect (this shell is its launcher) =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" -protect >"$LOG" 2>&1 & PID=$!
sleep 2
grep -iE "self-protection ARMED|running without it" "$LOG" | sed 's/^/   /'
echo "   agent pid=$PID"

echo ">>> ATTACK: a separate (non-launcher) process tries to SIGKILL the agent"
if bash -c "kill -9 $PID" 2>/tmp/kerr; then
	echo "   kill returned 0 (NOT blocked)"
else
	echo "   kill DENIED: $(tr -d '\n' </tmp/kerr | sed 's/.*kill: //')"
fi
sleep 1
if kill -0 "$PID" 2>/dev/null; then
	echo "   => agent SURVIVED the attacker's SIGKILL (tamper denied at the kernel)"
else
	echo "   => agent died (protection did not hold)"
fi

echo ">>> CONTROL: the legitimate launcher (this shell) stops it — always allowed"
kill -TERM "$PID" 2>/dev/null; sleep 1
kill -0 "$PID" 2>/dev/null && echo "   still running" || { echo "   stopped cleanly (protection lifts on exit)"; PID=""; }
rm -f /tmp/kerr
echo "== done =="

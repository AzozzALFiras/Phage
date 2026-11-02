#!/usr/bin/env bash
# selfdef-demo.sh — live proof that Phage defends its own sensory apparatus.
# The dominant 2025 evasion is "blinding": kill/stop/ptrace the security agent
# (or unhook its probes) instead of fighting its detections. Phage watches, in
# kernel, for attacks on ITSELF and flags them — even from root.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/selfdef-base.json
LOG=/tmp/selfdef-alert.log

cleanup(){ pkill -x phaged 2>/dev/null||true; rm -f /tmp/ptrace_poc /tmp/ptrace_poc.c "$STATE" "$LOG"; }
trap cleanup EXIT

echo "== build a ptrace-attach PoC (a debugger/injector attaching to a process) =="
cat > /tmp/ptrace_poc.c <<'C'
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char **argv){
    pid_t p = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, p, 0, 0);   /* fires create-side hook even if yama denies */
    sleep(1);
    ptrace(PTRACE_DETACH, p, 0, 0);
    return 0;
}
C
clang -O2 -o /tmp/ptrace_poc /tmp/ptrace_poc.c && echo built

echo "== learn a brief baseline =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 &
LP=$!; sleep 1
for i in $(seq 1 10); do ls / >/dev/null; date >/dev/null; done
sleep 1; kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null

echo "== start the agent (alert) =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >"$LOG" 2>&1 &
sleep 2
PID=$(pgrep -x phaged | head -1)
echo "agent pid=$PID, armed for self-defense"

echo ">>> ATTACK 1: a process attaches ptrace to the agent (debugger/injector)"
/tmp/ptrace_poc "$PID"
sleep 1
grep -iE "tamper|self.defense" "$LOG" | sed 's/^/   /' || echo "   (none)"

echo ">>> ATTACK 2: a non-supervisor shell sends SIGKILL to the agent"
kill -KILL "$PID" 2>/dev/null
sleep 1
echo "   agent process alive now? $(pgrep -x phaged >/dev/null && echo yes || echo killed)"
echo "   what the agent logged before dying:"
grep -iE "tamper|self.defense" "$LOG" | sed 's/^/   /' || echo "   (nothing — see note)"
echo
echo "NOTE: ptrace is caught live (agent survives). A SIGKILL races the agent's"
echo "own teardown; if the agent dies before draining the event, the dead-man's-"
echo "switch (telemetry suddenly stops) is the backstop — rule engines can't do that."
echo "== done =="

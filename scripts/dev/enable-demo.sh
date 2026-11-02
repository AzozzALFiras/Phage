#!/usr/bin/env bash
# enable-demo.sh — live proof that Phage catches the SETUP of a kernel exploit
# before escalation: a service-spawned process creating an unprivileged user
# namespace (create_user_ns) — the common enabler of Linux LPE. Detection is
# behavioural: a program doing an enabling op it has no history of on this host.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/enable-base.json

cleanup(){ pkill -x phaged 2>/dev/null||true; rm -f /tmp/kexp /tmp/kexp.c "$STATE"; systemctl reset-failed 'proof-ns*' 2>/dev/null||true; }
trap cleanup EXIT

echo "== build a PoC that performs the enabling op (unshare userns + brief sleep) =="
cat > /tmp/kexp.c <<'C'
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
int main(void){ unshare(CLONE_NEWUSER); sleep(2); return 0; }
C
clang -O2 -o /tmp/kexp /tmp/kexp.c && echo built

echo "== baseline: Phage learns normal behaviour, incl. a legit admin creating a userns =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/tmp/enable-learn.log 2>&1 &
LP=$!; sleep 1
for i in $(seq 1 12); do
  ls / >/dev/null; date >/dev/null; /bin/bash -c true
  unshare -Ur true 2>/dev/null || true     # benign userns by the admin tool, in-session
done
sleep 1; kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
echo "baseline: $(wc -c < "$STATE") bytes"

echo "== alert mode =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >/tmp/enable-alert.log 2>&1 &
AP=$!; sleep 1

echo ">>> CONTROL: the admin tool creates a userns again (known actor)"
unshare -Ur true 2>/dev/null || true
sleep 1
echo "   control verdict (expect none):"
grep -E "score=" /tmp/enable-alert.log | grep -i "kernel-enabling\|op:" | sed 's/^/     /' || true

echo ">>> ATTACK: a session-less service process sets up a kernel exploit (userns)"
systemd-run --quiet --unit=proof-ns -p User=nobody --wait /tmp/kexp 2>/dev/null || true
systemctl reset-failed proof-ns.service 2>/dev/null || true
sleep 1
echo "   Phage verdict:"
grep -E "score=" /tmp/enable-alert.log | grep -iE "kernel-enabling|op: userns" | sed 's/^/     /'
kill -TERM "$AP" 2>/dev/null; wait "$AP" 2>/dev/null
echo "== done =="

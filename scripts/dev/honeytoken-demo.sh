#!/usr/bin/env bash
# honeytoken-demo.sh — live proof of honeytokens fused into the kernel sensor.
# Phage plants decoy credential files; any READ of one (nothing legitimate
# references them) is a near-zero-false-positive, top-severity alert — wired to
# the kernel open path, no cloud callback an attacker could block.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/ht-base.json
LOG=/tmp/ht.log
PID=""

cleanup(){ [ -n "$PID" ] && kill "$PID" 2>/dev/null; sleep 1; rm -f "$STATE" "$LOG" /root/.aws/credentials /root/.ssh/id_ed25519_backup /var/backups/.pgpass; }
trap cleanup EXIT

echo "== learn a brief baseline =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 & LP=$!
sleep 1; for i in $(seq 1 8); do ls / >/dev/null; cat /etc/hostname >/dev/null; done; sleep 1
kill -INT "$LP" 2>/dev/null; wait "$LP" 2>/dev/null

echo "== start the agent with -honeytokens (this shell is its launcher) =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" -honeytokens >"$LOG" 2>&1 & PID=$!
sleep 2
grep -i "honeytokens planted" "$LOG" | sed 's/^/   /'

echo ">>> CONTROL: a normal file read (not a decoy)"
cat /etc/hostname >/dev/null
sleep 1
grep -i "honeytoken" "$LOG" | grep -v planted | sed 's/^/   /' || echo "   (no alert — correct)"

echo ">>> ATTACK: an intruder greps /root for credentials and reads the decoy"
cat /root/.aws/credentials >/dev/null 2>&1 || true
sleep 1
echo "   Phage verdict:"
grep -iE "honeytoken decoy|planted honeytoken" "$LOG" | grep -v "planted:" | sed 's/^/     /'

echo "== stop (decoys are removed on exit) =="
kill "$PID" 2>/dev/null; sleep 1; PID=""
echo "   decoy still on disk? $([ -e /root/.aws/credentials ] && echo yes || echo removed)"
echo "== done =="

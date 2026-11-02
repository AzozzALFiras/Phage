#!/usr/bin/env bash
# preload-demo.sh — live proof that Phage catches a dynamic-linker hijack:
# a program launched with LD_PRELOAD / LD_AUDIT / GLIBC_TUNABLES in its
# environment, forcing a chosen .so (or tunable) into a legitimate program.
# The signal is behavioural — the exec carries a hijack var it normally doesn't.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/preload-base.json

cleanup(){ pkill -x phaged 2>/dev/null||true; rm -f /tmp/evillib.so "$STATE"; }
trap cleanup EXIT

echo "== build a harmless .so to preload =="
echo 'void f(void){}' | clang -shared -fPIC -x c -o /tmp/evillib.so - && echo built

echo "== baseline: Phage learns normal execs (none use LD_PRELOAD) =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/tmp/preload-learn.log 2>&1 &
LP=$!; sleep 1
for i in $(seq 1 20); do ls / >/dev/null; date >/dev/null; /usr/bin/id >/dev/null; /bin/bash -c true; sleep 0.1; done
sleep 1; kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
echo "baseline: $(wc -c < "$STATE") bytes"

echo "== alert mode =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >/tmp/preload-alert.log 2>&1 &
AP=$!; sleep 1

echo ">>> CONTROL: a normal program, no preload"
/usr/bin/id >/dev/null; sleep 1
echo "   control verdict (expect none):"
grep -E "score=" /tmp/preload-alert.log | grep -i "dynamic-linker" | sed 's/^/     /' || true

echo ">>> ATTACK: the same program, launched with LD_PRELOAD (service context)"
systemd-run --quiet --unit=proof-preload -p User=nobody --wait \
	/bin/bash -c 'LD_PRELOAD=/tmp/evillib.so /usr/bin/id >/dev/null 2>&1' 2>/dev/null || true
systemctl reset-failed proof-preload.service 2>/dev/null || true
sleep 2
echo "   Phage verdict:"
grep -E "score=" /tmp/preload-alert.log | grep -iE "dynamic-linker|LD_PRELOAD" | sed 's/^/     /'
kill -TERM "$AP" 2>/dev/null; wait "$AP" 2>/dev/null
echo "== done =="

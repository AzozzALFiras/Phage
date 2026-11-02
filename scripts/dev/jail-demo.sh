#!/usr/bin/env bash
# jail-demo.sh — live proof of auto-jail (M3): learn syscalls -> generate a
# least-privilege seccomp profile -> prove it enforces.
#
# To capture a COMPLETE profile (including process startup), we create a cgroup,
# point the profiler at it, and launch the service INTO it — so counting begins
# at the service's very first instruction. (Profiling an already-running systemd
# unit instead captures steady state; see -follow and docs/concepts/auto-jail.md.)
set -euo pipefail
cd /root/phage

OBJ=bpf/build/jail.bpf.o
OUT=/tmp/phage-jail-out
CG=/sys/fs/cgroup/phage-jail-demo
LABEL=phage-jail-demo
rm -rf "$OUT"; mkdir -p "$OUT"

cleanup() { kill "${PY:-}" 2>/dev/null || true; pkill -f "http.server 8099" 2>/dev/null || true; rmdir "$CG" 2>/dev/null || true; }
trap cleanup EXIT

echo "== create a cgroup and profile a web service from its first instruction =="
rmdir "$CG" 2>/dev/null || true
mkdir "$CG"
./bin/phage-jail -path "$LABEL" -bpf "$OBJ" -seconds 12 -out "$OUT" &
JAIL=$!
sleep 1
# launch python INTO the pre-targeted cgroup, then exec (same pid) -> full capture
( echo $BASHPID > "$CG/cgroup.procs"; exec python3 -m http.server 8099 --bind 127.0.0.1 ) &
PY=$!
sleep 1
( for i in $(seq 1 36); do curl -s -o /dev/null http://127.0.0.1:8099/ || true; sleep 0.25; done ) &
TRAFFIC=$!
wait "$JAIL" 2>/dev/null || true
wait "$TRAFFIC" 2>/dev/null || true

echo
echo "== ENFORCEMENT PROOF: the service's own interpreter, under the generated jail =="
echo "   attempts two high-risk syscalls the profile reported as blocked."
LIST=$(grep '^SystemCallFilter=' "$OUT/$LABEL.dropin.conf" | sed 's/^SystemCallFilter=//')
PROBE='import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
r = libc.unshare(0x10000000)   # CLONE_NEWUSER — container/userns escape primitive
print("  unshare() ->", r, "|", os.strerror(ctypes.get_errno()))
r = libc.ptrace(0, 0, 0, 0)    # PTRACE_TRACEME — debug/inject other processes
print("  ptrace()  ->", r, "|", os.strerror(ctypes.get_errno()))'
echo "-- jailed (generated filter; EPERM on anything unlisted): --"
systemd-run --wait --pipe --quiet \
	-p "SystemCallFilter=$LIST" -p SystemCallErrorNumber=EPERM -p SystemCallArchitectures=native \
	python3 -c "$PROBE" 2>&1 | sed 's/^/  /' || true
echo "-- control, no jail: --"
python3 -c "$PROBE" 2>&1 | sed 's/^/  /'

echo
echo "== done =="

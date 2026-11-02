#!/usr/bin/env bash
# lock-demo.sh — live proof of eBPF-LSM exec-lock (M3 enforcement).
#
# Starts a web service, exec-locks its cgroup, and shows that a process in that
# cgroup can no longer execve a new program (a reverse shell / injected command
# is denied at the kernel) — while the service itself keeps serving and every
# other cgroup is unaffected. Safe: only the one named cgroup is locked, and the
# lock is lifted the instant phage-jail exits.
set -euo pipefail
cd /root/phage

OBJ=bpf/build/jail_lsm.bpf.o
UNIT=phage-webdemo

cleanup() { kill "${LOCK:-}" 2>/dev/null || true; systemctl stop "$UNIT.service" 2>/dev/null || true; systemctl reset-failed "$UNIT.service" 2>/dev/null || true; }
trap cleanup EXIT

grep -q bpf /sys/kernel/security/lsm && echo "BPF LSM active: yes" || { echo "BPF LSM NOT active"; exit 1; }

echo "== start web service =="
systemctl reset-failed "$UNIT.service" 2>/dev/null || true
systemd-run --unit="$UNIT" --quiet python3 -m http.server 8099 --bind 127.0.0.1
sleep 1
CG=$(systemctl show -p ControlGroup --value "$UNIT.service")
FULL="/sys/fs/cgroup$CG"
echo "service cgroup: $CG"
echo "service serves HTTP: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8099/)"

# try_exec: join the service cgroup, prove membership (shell builtins only), then
# attempt to execve a new program — exactly what a webshell/reverse shell does.
try_exec() {
	bash -c "echo \$\$ > $FULL/cgroup.procs
	         printf 'joined: %s\n' \"\$(< /proc/self/cgroup)\"
	         exec /bin/echo '  -> exec SUCCEEDED (a shell could spawn here)'" 2>&1 \
		|| echo "  -> exec DENIED (rc=$?) — no new program can start in this cgroup"
}

echo "== BEFORE lock: exec inside the service cgroup =="
try_exec

echo "== apply eBPF-LSM exec-lock on the service =="
./bin/phage-jail lock -unit "$UNIT.service" -bpf "$OBJ" &
LOCK=$!
sleep 2

echo "== AFTER lock: same attempt inside the service cgroup =="
try_exec

echo "== is the service itself still alive? =="
echo "service serves HTTP: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8099/)  state: $(systemctl is-active "$UNIT.service")"

echo "== collateral check: exec OUTSIDE the locked cgroup still works =="
/bin/echo "  -> outside-cgroup exec OK"

echo "== release the lock (phage-jail exits) =="
kill "$LOCK" 2>/dev/null || true; wait "$LOCK" 2>/dev/null || true; LOCK=
sleep 1
echo "== AFTER release: exec inside the cgroup works again =="
try_exec

echo "== done =="

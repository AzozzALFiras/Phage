#!/usr/bin/env bash
# lock-demo.sh — live proof of eBPF-LSM exec-lock with a LEARNED allowlist (M3).
#
# A service legitimately runs a helper (/bin/date) in a loop. phage-jail learns
# that, then enforces: the learned helper may still exec, but a never-seen
# program (bash, id) — exactly what an exploit would spawn — is denied at the
# kernel. The service keeps running; other cgroups are untouched; the lock lifts
# when phage-jail exits.
set -euo pipefail
cd /root/phage

OBJ=bpf/build/jail_lsm.bpf.o
UNIT=phage-jaildemo

cleanup() { kill "${LOCK:-}" 2>/dev/null || true; systemctl stop "$UNIT.service" 2>/dev/null || true; systemctl reset-failed "$UNIT.service" 2>/dev/null || true; rm -f /tmp/jail-e; }
trap cleanup EXIT

grep -q bpf /sys/kernel/security/lsm && echo "BPF LSM active: yes" || { echo "BPF LSM NOT active"; exit 1; }

echo "== start a service that legitimately execs /bin/date every second =="
systemctl reset-failed "$UNIT.service" 2>/dev/null || true
systemd-run --unit="$UNIT" --quiet /bin/bash -c 'while true; do /bin/date >/dev/null; /bin/sleep 1; done'
sleep 1
CG=$(systemctl show -p ControlGroup --value "$UNIT.service")
FULL="/sys/fs/cgroup$CG"
echo "service cgroup: $CG  state: $(systemctl is-active "$UNIT.service")"

# try_exec: join the service cgroup, then attempt to execve $*  (what a webshell does)
try_exec() {
	if bash -c "echo \$\$ > $FULL/cgroup.procs; exec $* >/dev/null 2>/tmp/jail-e"; then
		echo "  [$*] -> ALLOWED"
	else
		echo "  [$*] -> DENIED: $(tail -1 /tmp/jail-e)"
	fi
}

echo "== learn (6s) then enforce the allowlist =="
./bin/phage-jail lock -unit "$UNIT.service" -bpf "$OBJ" -learn 6 &
LOCK=$!
sleep 9   # 6s learn + margin for the switch to enforce

echo "== under enforcement, attempt execs inside the service cgroup =="
try_exec /bin/date +%s          # learned helper — should be ALLOWED
try_exec /bin/bash -c :         # never seen — should be DENIED
try_exec /usr/bin/id            # never seen — should be DENIED

echo "== the service itself is still running? =="
systemctl is-active "$UNIT.service"

echo "== collateral: exec OUTSIDE the jailed cgroup still works =="
/usr/bin/id -un >/dev/null && echo "  outside exec OK"

echo "== release (phage-jail exits) and re-test =="
kill "$LOCK" 2>/dev/null || true; wait "$LOCK" 2>/dev/null || true; LOCK=
sleep 1
try_exec /bin/bash -c :         # now unrestricted again

echo "== done =="

